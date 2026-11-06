# Migration plan: consolidate onto the EAS repo

This repo (`SurfaceScanner-public`, remote `jonvsec/EAS`) is the single source of
truth going forward. This document records what exists elsewhere and what to do
with it. Nothing is moved or deleted by this file. Every action below is
reviewed by a human before it runs, and no client data or secret ever reaches
the public remote.

## The landscape

| Location | Role | Action |
|---|---|---|
| `Desktop/SurfaceScanner-public` | Clean, git-tracked, remote EAS | Canonical. Keep. Add SDD flow (done). |
| `Desktop/SurfaceScanner` (2.2G, 0 commits) | Old Frankenstein, untracked | Archive read-only after salvage below. Do not merge code wholesale. |
| `~/surfacescanner-data` (19M) | Clean DATA layout, engagements/ | Canonical data root (`SURFACESCANNER_DATA`). Keep. |
| `~/SurfaceScanner_ClientData` (82M, old) | Superseded client data | Archive read-only. Confirm nothing newer than `surfacescanner-data`. |
| `Desktop/SJ/Templates/SurfaceScanner/eas_template_build.py` | Stray report builder | Review against `tools/surface_report.py`, fold in or drop. |
| `Desktop/Personal/AI/SurfaceScanner_Dossier_v4.docx` | Old dossier export | Archive. Superseded by v9 inside the Frankenstein. |

## Salvage from the Frankenstein, as specs not as copied code

The Frankenstein holds knowledge worth keeping. It does not hold code worth
copying blind. For each item below, the knowledge becomes a spec or a doc in
this repo, and only then is any code re-implemented through the flow.

| In the Frankenstein | What it is | Where it should land here |
|---|---|---|
| `CLAUDE.md` (37KB) | Old agent context | Distil the still-true rules into this repo's agent context. Drop the rest. |
| `DOSSIER.md` (93KB), `SurfaceScanner_Dossier_v9.md` | Capability dossiers | Mine for layer requirements. Each capability becomes an `specs/NNN-*` slice. |
| `LESSONS.md` (16KB) | Hard-won lessons | Fold the ones that are still rules into the constitution or the relevant spec. |
| `OPERATOR-ASSISTED-TESTS.md` | Manual test playbook | Becomes completion-criteria and validation notes in the relevant specs. |
| `BACKLOG_*.md` | Backlog items | Becomes the slice roadmap in `specs/README.md`. |
| `layer*/` python | Old implementations | Reference only. Re-implement promoted phases through a spec, never bulk copy. |
| `config.<client>.yaml`, per-client run scripts, `reports/`, `logs/`, `.env` | Client data and secrets | Never comes into the repo. Stays in or moves to `SURFACESCANNER_DATA`. |

## Order of work

1. SDD skeleton in place (constitution, specs structure, templates). Done.
2. Confirm `~/surfacescanner-data` is the only live data root. Point every
   `.env` at it. Archive `SurfaceScanner_ClientData` read-only.
3. Write the slice roadmap into `specs/README.md` from the backlogs and dossiers.
4. First real slice: the uncommitted in-flight work in this repo
   (`dmarc_watch.py`, `estate_expander.py`, wayback and prefix sweeps,
   `evidence_capture.py`). Spec it, then bring it to green under the flow.
5. Only after that, archive the Frankenstein tree read-only.

## Hard rules during migration

- No bulk copy of old code into this repo. Knowledge first, re-implementation
  through a spec second.
- No client data, scope, report or secret is committed or pushed. Those live in
  `SURFACESCANNER_DATA` only.
- Nothing in the Frankenstein is deleted until it is archived and the salvage is
  confirmed landed here.
