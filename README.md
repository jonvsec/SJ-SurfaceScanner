# SurfaceScanner

External attack surface engine. This repository starts with the **lookalike /
brand-protection vertical** and grows one phase at a time. The full folder
structure is kept from the start so the architecture is visible, with each
not-yet-promoted phase marked WIP.

## What is here today

The lookalike pipeline finds the domains an attacker would register to
impersonate a brand, keeps only the ones that actually exist, scores each one on
a SEV1 to SEV5 scale, and emits a sanitised, ingest-ready signal file. It is
fully local and uses no AI.

```
core/                 path resolution, rate limiting, network boundary, scope guard
layer1/               brand_protection, newly_registered_domains, shared helpers
layer2/subdomain/     cert transparency, passive and active subdomain enumeration
layer2/network/       zone transfer
layer2_5/             favicon_correlation (favicon hashing reused by the enrichers)
tools/                lookalike_watch, lookalike_report, certstream_watch,
                      subdomain_watch, panel (read-only operator console)
scope_parser.py       engagement scope loader
```

Two phases are promoted so far. The lookalike pipeline, and subdomain
enumeration (passive certificate transparency and aggregators, active DNS
bruteforce, resolution and takeover detection). Both feed the same per-client
signal file and both appear as autowatcher phases in the operator console.

For why the engine runs, the systemd-driven watch loop, and how the layers,
console and signals fit together, see `ARCHITECTURE.md`.

## Code vs data

Code and engagement data are kept strictly apart, by design, so the repository
never holds client scopes, outputs or reports.

- `SURFACESCANNER_ROOT` is the code (this repo). Only code assets live here.
- `SURFACESCANNER_DATA` is engagement data, OUTSIDE the repo. Outputs, reports,
  logs and signals are written per client under `DATA/engagements/<client>/`.

## Quick start

```bash
cp .env.example .env            # set SURFACESCANNER_ROOT and SURFACESCANNER_DATA
uv sync                         # or: pip install -e .

# one cycle against a scope, signals land under the client's own data dir
python tools/lookalike_watch.py --scope scopes/example.yaml --mode semi --once

# build the Excel deliverable
python tools/lookalike_report.py --scope scopes/example.yaml

# run the real-time CertStream watcher
python tools/certstream_watch.py --scope scopes/example.yaml
```

A scope file carries engagement data only (what to scan), never configuration:

```yaml
target:
  name: Example Corp
domains:
  - example.com
mode: passive
data_classification: SEMI-PUBLIC
```

## Severity

Mail capability dominates. A lookalike with MX records can send and receive mail
as the brand, so it ranks above a name that only resolves. A live login page, a
matching favicon and visual similarity raise it further. SEV1 is reserved for a
confirmed live clone.

## Roadmap

The remaining phases (corporate intelligence, OSINT, subdomain and network
infrastructure, surface recon, breach exposure, kill chain) are promoted into
this repo phase by phase. Each `layerN/` folder holds a short status note until
its phase lands.

## Tests

```bash
pytest -q
```
