# Docs map: what each file is and when it is read

This is the index of the governance and reference files. If you are not sure
which file governs a piece of work, start here.

## Governance and reference files

| File | What it is | When it is read |
|---|---|---|
| `CLAUDE.md` | One line that imports `AGENTS.md` | Auto-loaded by the agent every session |
| `AGENTS.md` | Operational rules for every change | Auto-loaded every session |
| `docs/constitution.md` | Non-negotiable principles | Before every spec, plan and task |
| `specs/README.md` | SDD flow, slice roadmap, target package names | When starting or changing a slice |
| `specs/_templates/*` | Spec, plan and task templates | Copied when starting a slice |
| `specs/NNN-<slice>/` | One slice: spec, plan, tasks | While building that slice |
| `ARCHITECTURE.md` | The engine design, layers, signal format | When you need the big picture |
| `docs/ui-standards.md` | UI tokens and the canonical page structure | Before any UI or console-view work |
| `docs/security-standards.md` | OWASP Top 10 mapped to this app | Before route, handler or fetch work |
| `docs/CONTRIBUTING.md` | How to set up, build, test and extend | Human onboarding, once |
| `docs/MIGRATION-from-frankenstein.md` | What exists elsewhere and how to salvage it | During migration from the old tree |

## How the governance files chain together

```
SESSION START (the agent auto-loads these every time)
  CLAUDE.md --@import--> AGENTS.md
                            |-> docs/constitution.md   read before every spec / plan / task
                            |-> specs/README.md        roadmap + SDD flow + layer taxonomy
                            |-> ARCHITECTURE.md        the design reference

STARTING A SLICE (the SDD loop)
  specs/README.md -> copy specs/_templates/{spec,plan,tasks}.md
                       -> specs/NNN-<slice>/  spec.md -> plan.md -> tasks.md
                            ^ each must obey docs/constitution.md

CONDITIONAL (read only when relevant)
  before UI work      -> docs/ui-standards.md
  before route / fetch-> docs/security-standards.md
  human onboarding    -> docs/CONTRIBUTING.md
  during salvage      -> docs/MIGRATION-from-frankenstein.md

ENFORCEMENT (not prose, runs on its own)
  scripts/hooks/pre-commit   blocks client data, PII and secrets at commit time
  uv run pytest -q           the regression net, green before any change ships
```

## How a scan actually runs

```
systemd user timer      deploy/<name>@.timer      (one instance per engagement, %i = scope name)
       |
       v
systemd service         deploy/<name>@.service
       |  ExecStart: python tools/<runner>.py --scope $SURFACESCANNER_DATA/scopes/<slug>.yaml [--mode] --once
       v
RUNNERS (tools/)                               feeds
  certstream_watch.py   cert-transparency feed  -> layer1
  lookalike_watch.py    brand / lookalike        -> layer1
  subdomain_watch.py    subdomain passive|active -> layer2
  dmarc_watch.py        email / DNS security     -> layer2_5
  footprint_run.py      corporate dossier agent  -> layer0
  layer_watch.py --layer N   generic: runs EVERY module promoted into layerN
       |
       v   each module:  async run(scope, config, db) -> {"findings": [...]}
  layer0..layer4 / layer2_5 modules
       |   (lean on core/: config, scope_guard, controls, network, ratelimiter, prefilter)
       v
  sanitized SIGNALS (JSONL)   $SURFACESCANNER_DATA/engagements/<slug>/...
       |
       v   read-only
  tools/panel.py   operator console -> triage -> deterministic report (no AI, no client traffic)
```

Two support files worth naming: `tools/page_template.py` is the single source of
truth for client-page structure, and `tools/dev_watch.py` is the console
live-reload used only in development.
