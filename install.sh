#!/usr/bin/env bash
# SurfaceScanner — one-shot system installer
# Run once as your user (will prompt for sudo password when needed)
# Usage: bash install.sh

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; exit 1; }
step() { echo -e "\n${YELLOW}━━━ $1 ━━━${NC}"; }

# ── 1. Docker ────────────────────────────────────────────────────────────────
step "Installing Docker"
if ! command -v docker &>/dev/null; then
    sudo pacman -S --noconfirm docker docker-compose
    ok "Docker installed"
else
    ok "Docker already installed ($(docker --version | cut -d' ' -f3 | tr -d ','))"
fi

step "Enabling Docker service"
sudo systemctl enable --now docker
ok "Docker service running"

step "Adding $USER to docker group"
sudo usermod -aG docker "$USER"
ok "Added to docker group (re-login or run: newgrp docker)"

# ── 2. Ollama ────────────────────────────────────────────────────────────────
step "Installing Ollama"
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
    ok "Ollama installed"
else
    ok "Ollama already installed ($(ollama --version 2>/dev/null | head -1))"
fi

step "Enabling Ollama service"
sudo systemctl enable --now ollama
sleep 3  # give it a moment to start
ok "Ollama service running"

# ── 3. Ollama models ─────────────────────────────────────────────────────────
step "Pulling qwen3:72b (primary — ~43GB download, this will take a while)"
echo "   Speed: ~10 t/s on RTX 3090 with GPU+CPU offload"
echo "   Quality: best available for 24GB VRAM system"
ollama pull qwen3:72b
ok "qwen3:72b pulled"

step "Pulling qwen3:8b (fast fallback — ~5.5GB)"
ollama pull qwen3:8b
ok "qwen3:8b pulled"

step "Pulling nomic-embed-text (ChromaDB embeddings — 274MB)"
ollama pull nomic-embed-text
ok "nomic-embed-text pulled"

# ── 4. Start Docker stack ────────────────────────────────────────────────────
step "Starting Docker stack (PostgreSQL, Neo4j, ChromaDB, SearXNG)"
cd "$(dirname "$0")"

# Apply docker group without re-login using sg
sg docker -c "docker compose -f docker/docker-compose.yml up -d"
ok "Docker stack starting..."

echo "   Waiting for services to become healthy (up to 60s)..."
for i in $(seq 1 12); do
    sleep 5
    HEALTHY=$(sg docker -c "docker compose -f docker/docker-compose.yml ps" 2>/dev/null | grep -c "healthy" || true)
    RUNNING=$(sg docker -c "docker compose -f docker/docker-compose.yml ps" 2>/dev/null | grep -c "running" || true)
    echo "   [$((i*5))s] healthy=$HEALTHY running=$RUNNING"
    if [ "$HEALTHY" -ge 2 ] 2>/dev/null; then break; fi
done

# ── 5. Verify everything ─────────────────────────────────────────────────────
step "Verifying all tools"
FAILED=0
check_tool() {
    if command -v "$1" &>/dev/null || [ -f "$HOME/go/bin/$1" ]; then
        ok "$1"
    else
        warn "$1 not found"
        FAILED=$((FAILED+1))
    fi
}

check_tool subfinder
check_tool dnsx
check_tool amass
check_tool alterx
check_tool puredns
check_tool massdns
check_tool katana
check_tool nuclei
check_tool nmap
check_tool exiftool
check_tool wafw00f
check_tool httpx
check_tool dnstwist
check_tool docker
check_tool ollama

# --- Service-context tool resolution guard -----------------------------------
# The bug that printed "0 alive" for a live domain: the systemd --user services
# run with a thin PATH that does NOT include ~/go/bin, and the venv ships a
# Python `httpx` CLI that shadows the ProjectDiscovery prober. check_tool above
# passes anyway because it looks in ~/go/bin and uses your interactive shell.
# This block runs the SAME resolver the code uses, under a service-like PATH, so
# a tool that works in your shell but would be missing or the wrong binary under
# the service is caught at install time, not silently at scan time.
if [ -x ".venv/bin/python" ]; then
    echo "Verifying tools resolve under a service-like PATH..."
    if PATH="/usr/local/bin:/usr/bin:/bin" .venv/bin/python - <<'PYEOF'
import sys
from core.network import resolve_tool
bad = 0
for t in ("dnsx", "subfinder", "httpx", "puredns", "massdns", "alterx"):
    p = resolve_tool(t)
    if not p:
        print(f"  [WARN] {t}: NOT resolvable under service PATH"); bad += 1
    elif t == "httpx" and "go/bin" not in p:
        print(f"  [WARN] httpx resolves to {p}, not the ProjectDiscovery prober"); bad += 1
    else:
        print(f"  [ok] {t} -> {p}")
sys.exit(1 if bad else 0)
PYEOF
    then :; else
        warn "some tools resolve wrong or missing under the systemd services (see above). The code resolves Go tools by absolute path, but set PATH in .env to be safe."
    fi
fi

# Optional lookalike-pipeline tools. Absence is not fatal: each stage is
# tool-gated and skipped when the binary is missing.
#   dnstwist[full]  perceptual-hash (--phash) + HTML fuzzy-hash (--lsh) support
#   gowitness       screenshots of live lookalikes (brand_protection enrich_screenshot)
#   urlcrazy        extra permutation generator (brand_protection.extra_generators)
# Install: pip install "dnstwist[full]" ; go install github.com/sensepost/gowitness@latest
for t in gowitness urlcrazy; do
    command -v "$t" &>/dev/null && ok "$t (optional)" || warn "$t not found (optional)"
done

step "Verifying Ollama models"
ollama list

step "Verifying Docker services"
sg docker -c "docker compose -f docker/docker-compose.yml ps"

# ── 6. Done ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Run this to verify everything works:"
echo ""
echo -e "  ${YELLOW}uv run python tests/verify_install.py${NC}"
echo ""
if [ "$FAILED" -gt 0 ]; then
    warn "$FAILED tool(s) missing — see above"
fi
echo "Note: Docker group change requires re-login or run 'newgrp docker' first"
