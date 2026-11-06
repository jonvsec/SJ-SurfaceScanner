#!/usr/bin/env bash
# SurfaceScanner / Continuous EAS - from-zero installer for Debian
#
# Brings a clean Debian box (12 bookworm or newer, or Ubuntu) up to a state
# where the operator console and every promoted phase run. It is idempotent,
# so it is safe to run again after adding a tool. This file is the living
# install manifest: when a phase starts needing a new binary or library, add
# its install line in the matching section below and in scripts/TOOLS.md, so
# a fresh box always has everything.
#
#   sudo apt update
#   bash scripts/install-debian.sh
#
# It prompts for sudo only where a system package is installed. Everything
# else lands in this checkout (.venv) or the user home (~/go, ~/.local), so no
# step needs root it does not ask for.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC} $1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
step() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }
have() { command -v "$1" >/dev/null 2>&1 || [ -x "$HOME/go/bin/$1" ]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Versions we pin. The ProjectDiscovery and other Go tools need a current Go,
# newer than Debian stable ships, so Go is installed from upstream.
GO_VERSION="1.23.4"
INGEST_MODEL="${SURFACESCANNER_INGEST_MODEL:-qwen3:8b}"

# --------------------------------------------------------------------------
# 1. System packages from apt
# --------------------------------------------------------------------------
step "System packages (apt)"
# build-essential and libpcap-dev: building massdns and some Go tools.
# chromium: gowitness screenshots. nmap, whois, exiftool, jq: recon and report.
# python3-venv and pipx: the console venv and the python CLI tools.
APT_PACKAGES=(
  build-essential git curl wget unzip ca-certificates jq
  python3 python3-venv python3-pip pipx
  libpcap-dev nmap whois libimage-exiftool-perl
  p7zip-full default-jre-headless
  libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev libcairo2
)
sudo apt-get update -y
sudo apt-get install -y "${APT_PACKAGES[@]}"
# chromium is named chromium on Debian and chromium-browser on some Ubuntu
# releases, so try both and do not fail the run if neither is available (only
# the screenshot enrichment needs it).
sudo apt-get install -y chromium 2>/dev/null \
  || sudo apt-get install -y chromium-browser 2>/dev/null \
  || warn "chromium not installed, screenshot enrichment will be skipped"
ok "apt packages installed"

# --------------------------------------------------------------------------
# 2. Go toolchain (from upstream, pinned)
# --------------------------------------------------------------------------
step "Go ${GO_VERSION}"
NEED_GO=1
if have go; then
  CUR="$(go version 2>/dev/null | grep -oE 'go[0-9.]+' | head -1 | tr -d 'go')"
  [ "$(printf '%s\n' "1.21" "$CUR" | sort -V | head -1)" = "1.21" ] && NEED_GO=0
fi
if [ "$NEED_GO" = "1" ]; then
  ARCH="$(dpkg --print-architecture)"   # amd64 or arm64
  TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"
  curl -fsSLo "/tmp/${TARBALL}" "https://go.dev/dl/${TARBALL}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/${TARBALL}"
  ok "Go ${GO_VERSION} installed to /usr/local/go"
else
  ok "Go already current ($(go version | grep -oE 'go[0-9.]+' | head -1))"
fi
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
# Persist the PATH for future shells, once.
if ! grep -q 'usr/local/go/bin' "$HOME/.profile" 2>/dev/null; then
  echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> "$HOME/.profile"
fi

# --------------------------------------------------------------------------
# 3. Go-based recon tools
# --------------------------------------------------------------------------
step "Recon tools (go install)"
# Each line is one tool the scanner shells out to. Add a tool here when a phase
# starts using it, and record it in scripts/TOOLS.md.
go_install() {   # $1 binary name, $2 go module path
  if have "$1"; then
    ok "$1 already present"
  else
    echo "    installing $1 ..."
    GOBIN="$HOME/go/bin" go install "$2" && ok "$1 installed" || warn "$1 failed to install"
  fi
}
go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install dnsx      github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install katana    github.com/projectdiscovery/katana/cmd/katana@latest
go_install nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go_install alterx    github.com/projectdiscovery/alterx/cmd/alterx@latest
go_install puredns   github.com/d3mondev/puredns/v2@latest
go_install gowitness github.com/sensepost/gowitness@latest
go_install amass     github.com/owasp-amass/amass/v4/...@master

# --------------------------------------------------------------------------
# 4. massdns (built from source, puredns needs it)
# --------------------------------------------------------------------------
step "massdns"
if have massdns; then
  ok "massdns already present"
else
  TMP="$(mktemp -d)"
  git clone --depth 1 https://github.com/blechschmidt/massdns "$TMP/massdns"
  make -C "$TMP/massdns" >/dev/null
  sudo install -m 0755 "$TMP/massdns/bin/massdns" /usr/local/bin/massdns
  rm -rf "$TMP"
  ok "massdns installed to /usr/local/bin"
fi

# --------------------------------------------------------------------------
# 4b. jadx (APK static analysis, layer 2.5 apk_analysis)
# --------------------------------------------------------------------------
step "jadx (APK decompiler)"
JADX_VERSION="1.5.0"
if have jadx; then
  ok "jadx already present"
else
  TMP="$(mktemp -d)"
  if curl -fsSLo "$TMP/jadx.zip" \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"; then
    sudo mkdir -p /opt/jadx
    sudo unzip -oq "$TMP/jadx.zip" -d /opt/jadx
    sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
    ok "jadx ${JADX_VERSION} installed to /opt/jadx"
  else
    warn "could not download jadx, APK decompile falls back to strings"
  fi
  rm -rf "$TMP"
fi

# --------------------------------------------------------------------------
# 5. Python CLI tools (isolated with pipx)
# --------------------------------------------------------------------------
step "Python CLI tools (pipx)"
pipx ensurepath >/dev/null 2>&1 || true
pipx_install() {   # $1 package spec, $2 binary name
  if have "$2"; then ok "$2 already present"; else pipx install "$1" >/dev/null && ok "$2 installed" || warn "$2 failed"; fi
}
# dnstwist[full] adds perceptual-hash and fuzzy-hash support used by the
# lookalike enrichment. wafw00f fingerprints WAFs during surface recon.
pipx_install "dnstwist[full]" dnstwist
pipx_install wafw00f wafw00f

# --------------------------------------------------------------------------
# 6. The project itself (console and library) in a venv
# --------------------------------------------------------------------------
step "Project virtualenv"
if [ ! -x "$ROOT/.venv/bin/python" ]; then
  python3 -m venv "$ROOT/.venv"
  ok "created .venv"
fi
"$ROOT/.venv/bin/pip" install --quiet --upgrade pip
# Base dependencies are the console plus the promoted phases. The report extra
# (WeasyPrint for the PDF) and docmeta (python-docx for the Word report) back
# the console's Generate report button, so install them too. Other extras such
# as screenshots install on demand, see pyproject.toml.
"$ROOT/.venv/bin/pip" install --quiet -e "$ROOT[report,docmeta]"
ok "project installed into .venv (with report and docmeta extras)"

# --------------------------------------------------------------------------
# 7. Nuclei templates and puredns resolvers
# --------------------------------------------------------------------------
step "Data: nuclei templates and resolvers"
have nuclei && (nuclei -update-templates -silent >/dev/null 2>&1 && ok "nuclei templates updated" || warn "nuclei template update skipped")
RES="$ROOT/wordlists/resolvers.txt"
if [ ! -s "$RES" ]; then
  mkdir -p "$ROOT/wordlists"
  curl -fsSLo "$RES" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    && ok "resolvers list fetched to wordlists/resolvers.txt" || warn "could not fetch resolvers, add wordlists/resolvers.txt by hand"
else
  ok "resolvers list already present"
fi

# --------------------------------------------------------------------------
# 8. Local AI for ingestion (ollama), optional but recommended
# --------------------------------------------------------------------------
step "Local AI (ollama)"
if ! have ollama; then
  curl -fsSL https://ollama.com/install.sh | sh && ok "ollama installed" || warn "ollama install skipped"
else
  ok "ollama already present"
fi
if have ollama; then
  sudo systemctl enable --now ollama 2>/dev/null || true
  sleep 2
  # The console picks the smallest installed chat model for ingestion. A small
  # model keeps the one-off extraction fast. The ingestion still works without
  # ollama, it just falls back to a plain regex sweep.
  ollama pull "$INGEST_MODEL" >/dev/null 2>&1 && ok "pulled ${INGEST_MODEL}" || warn "could not pull ${INGEST_MODEL}, ingestion will use the regex fallback"
fi

# --------------------------------------------------------------------------
# 9. systemd user services for the autowatchers
# --------------------------------------------------------------------------
step "systemd user units"
# Let the user manager run the watchers without an open login session. This is
# what lets a scheduled sweep fire on a headless Debian server.
sudo loginctl enable-linger "$USER" 2>/dev/null || warn "could not enable linger, watchers only run while you are logged in"
bash "$ROOT/deploy/install-user-units.sh"
ok "watcher units installed"

# --------------------------------------------------------------------------
# 10. Verify
# --------------------------------------------------------------------------
step "Verify"
MISSING=0
for t in subfinder dnsx httpx katana nuclei alterx amass puredns massdns gowitness dnstwist wafw00f nmap exiftool jadx 7z; do
  if have "$t"; then ok "$t"; else warn "$t missing"; MISSING=$((MISSING+1)); fi
done
"$ROOT/.venv/bin/python" -c "import tools.panel" 2>/dev/null && ok "console imports" || warn "console import check skipped (run from repo root)"

echo ""
if [ "$MISSING" -gt 0 ]; then
  warn "$MISSING tool(s) missing. Each phase is tool-gated and skips a missing binary, but fill these for full coverage."
fi
echo -e "${GREEN}Done.${NC} Open a new shell so the PATH picks up Go tools, then start the console:"
echo "    PANEL_USER=redteam PANEL_PASSWORD=change-me .venv/bin/python tools/panel.py --host 127.0.0.1 --port 8787"
