# Tool manifest (Debian)

Every external tool and library the console and the promoted phases need on a
Debian box, and the one command that installs each. `scripts/install-debian.sh`
installs all of this in order and is safe to run again. This file is the living
list: when a phase starts needing a new tool, add a row here and the matching
line in the installer, so a from-zero box always has everything.

Run the whole thing with:

    bash scripts/install-debian.sh

## System packages (apt)

| Package | Why |
|---|---|
| build-essential | builds massdns and some Go tools |
| git, curl, wget, unzip, ca-certificates | fetch and build tools |
| jq | JSON handling in scripts |
| python3, python3-venv, python3-pip, pipx | the console venv and the python CLI tools |
| libpcap-dev | needed by some ProjectDiscovery tools |
| nmap | port and service checks (surface recon) |
| whois | registration data for lookalike ageing |
| libimage-exiftool-perl (exiftool) | document metadata extraction |
| chromium | gowitness screenshots (lookalike enrichment) |
| p7zip-full (7z) | unpack APKs for layer 2.5 apk_analysis |
| default-jre-headless | Java runtime jadx needs |
| libpango-1.0-0, libpangocairo-1.0-0, libgdk-pixbuf-2.0-0, libffi-dev, libcairo2 | WeasyPrint rendering for the PDF report |

    sudo apt-get install -y build-essential git curl wget unzip ca-certificates jq \
      python3 python3-venv python3-pip pipx libpcap-dev nmap whois libimage-exiftool-perl chromium

## Go toolchain

ProjectDiscovery and the other Go tools need a current Go, newer than Debian
stable ships, so it is installed from upstream and pinned.

    curl -fsSLo /tmp/go.tgz https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

## Recon tools (go install)

| Tool | Used by | Install |
|---|---|---|
| subfinder | passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| dnsx | DNS resolution and validation | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | HTTP probing and fingerprint | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| nuclei | takeover and template checks | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| alterx | permutation generation | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` |
| puredns | wordlist bruteforce resolve | `go install github.com/d3mondev/puredns/v2@latest` |
| gowitness | lookalike screenshots | `go install github.com/sensepost/gowitness@latest` |
| amass | active subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |

## massdns (built from source)

puredns drives massdns for fast resolution.

    git clone --depth 1 https://github.com/blechschmidt/massdns /tmp/massdns
    make -C /tmp/massdns && sudo install -m 0755 /tmp/massdns/bin/massdns /usr/local/bin/massdns

## jadx (APK static analysis)

layer 2.5 `apk_analysis` decompiles owned Android apps with jadx (falling back to
`strings` on the dex if jadx is missing) and unpacks them with 7z. jadx is a
pinned release, not an apt package.

    curl -fsSLo /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
    sudo unzip -oq /tmp/jadx.zip -d /opt/jadx && sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx

The module only downloads and analyses an APK once the operator sets
`apk_analysis.confirmed` and the package list in config, a deliberate human
opt-in. Without it, it reports which apps it would analyse and pulls nothing.

## Python CLI tools (pipx)

| Tool | Why | Install |
|---|---|---|
| dnstwist[full] | lookalike permutations, with perceptual and fuzzy hashing | `pipx install "dnstwist[full]"` |
| wafw00f | WAF fingerprint during surface recon | `pipx install wafw00f` |

## The project

Base dependencies are the console and the promoted phases. Optional extras
(screenshots, html, report, docmeta, recon, cli, store, ai) install on demand,
see `pyproject.toml`.

    python3 -m venv .venv && .venv/bin/pip install -e ".[report,docmeta]"

The `report` extra (WeasyPrint) renders the PDF report and `docmeta`
(python-docx) writes the editable Word report, both behind the console's
Generate report button (`tools/surface_report.py`). WeasyPrint needs the pango
and cairo system libraries listed above.

## Promoted layer watchers

Layers 0, 2.5, 3 and 4 run through one generic watcher, `tools/layer_watch.py`,
which drives every module present in that layer's package and emits EAS signals.
Its systemd units (`corp-intel@`, `surface-recon@`, `footprint-breach@`,
`killchain-intel@`) are written by `deploy/install-user-units.sh`. The modules
need no extra binaries beyond the recon tools above and the base Python deps
(httpx, dnspython, structlog), so `pip install -e .` is enough. Some layer 3
sources are API-key gated and skip themselves when the key is absent; add the
key to `.env` to enable them. Promoting more modules is dropping their file into
the layer package, no new tool or unit.

## Data

| What | Install |
|---|---|
| nuclei templates | `nuclei -update-templates` |
| puredns resolvers | `curl -fsSLo wordlists/resolvers.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt` |

## Local AI (ollama), optional

Ingestion reads a pasted client note with the local model and suggests scope
domains. It is local only and falls back to a plain regex sweep when ollama is
not running, so it is never required.

    curl -fsSL https://ollama.com/install.sh | sh
    sudo systemctl enable --now ollama
    ollama pull qwen3:8b

## systemd user units

The autowatchers run as systemd user units. Lingering lets them fire on a
headless server with no open session.

    sudo loginctl enable-linger "$USER"
    bash deploy/install-user-units.sh
