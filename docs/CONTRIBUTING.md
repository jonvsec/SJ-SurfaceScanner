# Contributing to SurfaceScanner (EAS)

How to set up, build, test and extend this engine. Read this once before your
first change. Read `constitution.md` and `../AGENTS.md` before every change. The
constitution wins over anything here.

## What this project is

A continuous external attack surface engine. It rediscovers a target's public
surface over time, scores every finding SEV1 to SEV5, and raises new ones as
alerts an operator triages into a deliverable. It is file driven, has no database
and no orchestrator, and runs as short-lived systemd user units. See
`../ARCHITECTURE.md` for the loop, the layers and the signal format.

## The one rule that matters most

Code and client data are strictly apart.

- Code lives in this repo (`SURFACESCANNER_ROOT`).
- Every engagement's scopes, outputs, reports, logs and signals live in
  `SURFACESCANNER_DATA`, a path OUTSIDE this repo.
- A real finding, count, client name, host or email never enters the repo. Not
  in a spec, not in a doc, not in a code comment. If you need to explain why a
  control exists, state the general principle, never the engagement that taught
  it to you.

The repo is public-shaped. Assume anything you commit could be read by anyone.

## Prerequisites

- Python 3.12 or newer
- `uv` for dependency management (https://docs.astral.sh/uv/)
- Standard recon tooling on PATH for the active phases (see `../scripts/TOOLS.md`)

## Set up

```
git clone <your-remote> SJ-Surfacescanner
cd SJ-Surfacescanner
uv sync
cp .env.example .env            # then point it at your SURFACESCANNER_DATA
```

### Install the pre-commit guard (required)

The repo ships a guard that blocks client data, PII and secrets at commit time.
Git does not share hooks automatically, so each clone wires it once:

```
git config core.hooksPath scripts/hooks
```

Then create a client-name denylist OUTSIDE the repo so the guard can block names
too. One name per line. Mind that matching is substring, so prefer a distinctive
multi-word or domain form over a short word:

```
mkdir -p "$SURFACESCANNER_DATA"
$EDITOR "$SURFACESCANNER_DATA/client-denylist.txt"
```

The guard also reads `$SS_CLIENT_DENYLIST` or
`~/.config/surfacescanner/client-denylist.txt` if either is set. It checks
secrets and patterns even with no denylist present. To add a true placeholder
false positive, edit `scripts/hooks/allowlist.txt`, never to add a real value.

## Run

```
uv run pytest -q                                  # tests
python tools/panel.py                             # operator console, read-only
python tools/lookalike_watch.py --scope scopes/example.yaml --mode semi --once
```

Deployed, each runner is a systemd user unit. See `../deploy/`.

## How to make a change: the SDD flow

Nothing new is implemented without a spec. The flow, per slice of work:

```
Constitution -> Spec -> Clarify -> Plan -> Tasks -> Implement -> Validate
```

1. Start a slice folder `specs/NNN-<slice-name>/` and copy the three templates
   from `specs/_templates/`. Fill `spec.md` first (what and why, requirements as
   RF-1.. in EARS). Mark every unknown as `[NEEDS CLARIFICATION: question]`.
2. Clarify the unknowns with the operator before planning.
3. Write `plan.md` (modules, data shape, decisions with the rejected option,
   test strategy). No code in the plan.
4. Write `tasks.md` (T1..Tn, dependency ordered, each with its RF and a
   "Done when:" check). Each task is small.
5. Implement one task at a time, tests first, then stop and report.
6. Validate RF by RF. A task is not done while a test is red or a check was not
   run. End every task with `uv run pytest -q` and show the result.

Changing a shipped slice: update the spec first, show the diff, then re-plan.
The spec never falls behind the code. See `../specs/README.md` for the slice
roadmap and the target package names.

## House style

- Python 3.12+, standard library first. The scanning flow imports no AI stack
  and no datastore.
- Every layer module exposes `async def run(scope, config, db=None)` and returns
  `{"findings": [...]}`. A module that lacks a key or a tool skips itself and
  contributes nothing. It never fails its layer.
- Code and identifiers in English. Repo prose stays plain and human, with no em
  dashes and no semicolons.
- Respect the scope gate (passive, semi, active) on every capability. A semi or
  active command never fires inside a passive scope.
- Do not edit `tools/panel.py` without an explicit go. It is the operator
  console and its triage state belongs to the operator.

## Before you push

- `uv run pytest -q` is green.
- The pre-commit guard passed without `--no-verify`.
- No client name, finding, host, email or secret is in the diff.
- The change is covered by a spec under `specs/`.
