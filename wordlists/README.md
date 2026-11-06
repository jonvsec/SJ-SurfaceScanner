# Wordlists and resolvers for Layer 2 subdomain enumeration

Layer 2 runs tool-gated. A module that cannot find its wordlist or resolver list
falls back to a tiny builtin and logs a warning, it never errors. So the engine
runs without any of the files below, but coverage is much weaker. Install them
on each host that runs the subdomain watcher.

No em dashes, no en dashes, no semicolons.

## What each file is for

| File | Used by | Required | What it does |
|---|---|---|---|
| `resolvers.txt` | prefix sweep, bruteforce (puredns) | Strongly recommended | Trusted DNS resolvers for mass resolution. A ships a 6-entry starter, replace it with a validated list. |
| `subdomains.txt` | bruteforce (operator override) | Optional | If present, this list wins over every SecLists path. Drop a target-tuned list here. |
| SecLists DNS lists | bruteforce (auto-detected) | Recommended | The real brute-force wordlists. Found by path, see below. |
| `tlds.txt` | TLD expansion (future) | Shipped | IANA TLD list. |

The bruteforce module auto-detects a SecLists checkout in this order and uses
the first that exists: `wordlists/SecLists/...`, `~/SecLists/...`,
`/usr/share/seclists/...`, `/usr/share/wordlists/seclists/...`. So either symlink
SecLists into this folder or install it system-wide.

## Tools these modules need (install first)

ProjectDiscovery tools and puredns/massdns. On Arch, Go is `pacman -S go`.

```bash
# ProjectDiscovery suite
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# massdns (puredns depends on it)
git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
make -C /tmp/massdns && sudo cp /tmp/massdns/bin/massdns /usr/local/bin/

# puredns (wildcard-filtering resolver wrapper)
go install github.com/d3mondev/puredns/v2@latest

# amass (deep passive, already checked by install.sh)
go install github.com/owasp-amass/amass/v4/...@master
```

Make sure `~/go/bin` is on `PATH` (install.sh checks both `PATH` and `~/go/bin`).

## Wordlists: download

### SecLists (the DNS brute lists)

```bash
# system-wide (Arch)
sudo pacman -S seclists          # lands in /usr/share/seclists

# or a local checkout symlinked into this folder
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists
ln -s ~/SecLists wordlists/SecLists
```

The module looks for these specific files, best first:
`bitquark-subdomains-top100000.txt`, `n0kovo_subdomains.txt`,
`subdomains-top1million-110000.txt`, `dns-Jhaddix.txt`.

### Assetnote (best-curated, updated monthly)

Browse the index at `https://wordlists.assetnote.io/` and copy the current
dated DNS list URL (the filenames carry a date, for example
`.../data/subdomains/<date>_best-dns-wordlist.txt`, so do not hardcode an
undated path). Then:

```bash
mkdir -p wordlists/assetnote
# paste the dated URL you copied from the index:
curl -o wordlists/assetnote/best-dns.txt "<assetnote-best-dns-url>"
# make it the default brute list:
ln -sf assetnote/best-dns.txt wordlists/subdomains.txt
```

Size-to-time-budget guidance (the bruteforce module scales its own timeout to
match): under 10k = 1 to 2 minutes, 10k to 100k = the default working depth,
100k to 1M = thorough multi-hour, over 1M = exhaustive, reserve for a long
engagement.

### Resolvers (replace the 6-entry starter)

A stale or poisoned resolver list ruins a mass resolve, so validate it:

```bash
go install github.com/vortexau/dnsvalidator@latest
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 \
  -o wordlists/resolvers.txt
```

## API keys (optional, raise passive coverage)

These only widen coverage, absence just loses sources, nothing errors.

- Subfinder sources (FOFA, ZoomEye, Netlas, SecurityTrails, Shodan, Censys, and
  more): set in `~/.config/subfinder/provider-config.yaml`.
- `CERTSPOTTER_API_KEY`: raises the Certspotter CT page cap past one page.
- `CENSYS_API_ID` and `CENSYS_API_SECRET`: enables the Censys CT fallback in the
  cert-transparency chain.
