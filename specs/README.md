# Specs

This is where SurfaceScanner is built with Spec-Driven Development. Nothing new
gets implemented without a spec here. Read `../docs/constitution.md` first. It
governs every spec in this folder.

## The flow

For each slice of work, in order:

```
Constitution  ->  Spec  ->  Clarify  ->  Plan  ->  Tasks  ->  Implement  ->  Validate
(one time)        what/why   QA pass     how      <30 min    one task       RF by RF
                                                   each       tests first
```

Change later (new requirement on a shipped slice): update the spec first, show
the diff, then re-plan. The spec never falls behind the code.

## One slice per folder

```
specs/NNN-<slice-name>/
  spec.md     what the slice does and why, requirements as RF-1.. in EARS
  plan.md     modules, data, decisions with the rejected option, test strategy
  tasks.md    T1..Tn, dependency ordered, each with its RF and a "Done when:"
```

A slice is a thin vertical that can be demoed on its own. In this engine the
natural slice is a layer, or one capability promoted into a layer. Keep a spec
to roughly one page. If it grows past that, it is two slices.

## The layers as slices

The engine grows one phase at a time. This is the slice axis.

| Layer | Name | Status | Spec |
|---|---|---|---|
| 0 | Corporate Intelligence | partial | tbd |
| 1 | OSINT (lookalike, brand, cert feed) | shipped | retro-spec optional |
| 2 | Subdomain and network infrastructure | shipped | retro-spec optional |
| 2.5 | Surface recon (email/DNS security, favicon) | shipped | retro-spec optional |
| 3 | Digital footprint and breach | shipped | retro-spec optional |
| 4 | Kill chain and sector intel (EPSS, CISA KEV) | shipped | retro-spec optional |

Already-shipped layers do not need a spec written backwards unless we are about
to change one. The discipline starts with the next change.

## Target package names

The folders are numbered (`layer0..layer4`, plus the half-numbered `layer2_5`).
The number is an implementation detail that leaked into the filesystem, and it
does not read like the console, which names each phase. The target is to demote
the number to metadata and name each package for what it does, matching the UI.

| Folder today | Console name | Target package |
|---|---|---|
| `layer0` | Corporate Intelligence | `corp_intel` |
| `layer1` | OSINT | `osint` |
| `layer2` | Subdomain and network infrastructure | `infra` |
| `layer2_5` | Surface recon | `surface_recon` |
| `layer3` | Digital footprint and breach | `breach` |
| `layer4` | Kill chain and sector intel | `killchain` |

Do not rename in one pass. That is import churn with no behaviour change and
real risk. Rename each package as its slice is re-implemented through the flow,
so `layer2_5` and the numbering retire themselves slice by slice. By the time
every slice has a spec, the tree reads like the console.

## Where the discipline starts

The work currently uncommitted in this repo (for example `dmarc_watch.py`,
`estate_expander.py`, the wayback and prefix subdomain sweeps, `evidence_capture.py`)
landed without a spec. That is the first place to apply the flow going forward.
Each of those becomes an `NNN-<name>/` slice with its own spec, plan and tasks
before it is extended further.

## Templates

Copy from `_templates/` when starting a slice. Do not skip sections. Mark every
unknown as `[NEEDS CLARIFICATION: concrete question]` rather than guessing.
