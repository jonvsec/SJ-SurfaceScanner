# AGENTS.md: SurfaceScanner (EAS)

## Project
Continuous external attack surface engine, per client and per engagement. It
rediscovers a target's public surface over time, scores every finding SEV1 to
SEV5, and raises new ones as alerts an operator triages into a deliverable. The
engine is file driven, has no database and no orchestrator, and runs as
short-lived systemd user units. The operator console in `tools/panel.py` is a
read-only stdlib HTTP view over the signal files. See `ARCHITECTURE.md` for the
loop, the layers and the signal format.

## Commands
- Install deps: `uv sync`
- Run one cycle: `python tools/lookalike_watch.py --scope scopes/example.yaml --mode semi --once`
- Tests: `uv run pytest -q`
- Console: `python tools/panel.py`

## Style and conventions
- Python 3.12+, standard library first. The scanning flow imports no AI stack
  and no datastore.
- Code and identifiers in English. Repo prose stays plain and human, with no em
  dashes and no semicolons.
- Every layer module exposes `async def run(scope, config, db=None)` and returns
  `{"findings": [...]}`.

## Rules
- Read `docs/constitution.md` and the active spec under `specs/` before touching
  code. The constitution wins over anything here.
- No behaviour is implemented unless a spec describes it. If a decision is
  missing, stop and ask.
- Never commit or push client data, scopes, outputs, reports or secrets. Those
  live in `SURFACESCANNER_DATA` outside this repo.
- Respect the scope gate (passive, semi, active) on every capability. A semi or
  active command must never fire inside a passive scope.
- Do not edit `tools/panel.py` without an explicit go. It is the operator
  console and its triage and control state belongs to the operator.
- Keep two backlogs apart. The backlog of what to build lives in the repo under
  `specs/` (roadmap in `specs/README.md`, one slice per `specs/NNN-*/`). The
  record of what an engagement found never enters the repo. It stays in
  `SURFACESCANNER_DATA` or in operator notes outside the tree. Never write a
  real finding, count, client name, host or email into a spec, a doc or a code
  comment. State the general principle instead.
- A pre-commit guard (`scripts/hooks/pre-commit`) blocks client data, PII and
  secrets. Do not disable it. If it fires, fix the content, do not pass
  `--no-verify` to get around a true positive.
- Surgical changes. Touch only what the task requires. Do not refactor code that
  is not broken, and do not rewrite a working module to make it shorter or
  nicer. Every changed line traces to the spec. If you spot unrelated dead code,
  mention it, do not delete it. See constitution principle 11.
- Before UI work read `docs/ui-standards.md` and copy the tokens and the
  structure there. Never invent a spacing, width, radius or colour value.
- Before touching a console route, a request handler or anything that fetches a
  URL, read `docs/security-standards.md` and treat it as a required check.
- `docs/README.md` is the map of every doc and what triggers it. Start there if
  you are unsure which file governs the work.

## Testing rules
- Never drive triage state from a test. Do not POST to `/vuln-action` (confirm,
  false positive, reopen, send) to exercise code. Those statuses belong to the
  operator, not to a test run.
- Tests use tmp paths and never write into `SURFACESCANNER_DATA` or a real
  engagement. No test sends traffic to a client.

## At the end of any task
- Run `uv run pytest -q` and show the result. A task is not done while a test is
  red or a required check was not run.
