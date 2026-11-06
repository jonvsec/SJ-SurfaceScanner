# Constitution of SurfaceScanner (EAS)

Non-negotiable principles. Every spec, plan and task must obey them. If a change
would break one of these, it stops and the decision comes to a human first.

1. **The spec rules.** No behaviour ships unless a spec under `specs/` describes
   it. When a decision is missing, work stops and asks. It never assumes a gap
   and fills it silently.

2. **Stay off the client by default.** Every capability declares a gate
   (passive, semi, active). The network boundary enforces the scope mode, so a
   semi or active command can never fire inside a passive scope. Most phases are
   contactless.

3. **Code and client data stay strictly apart.** `SURFACESCANNER_ROOT` is this
   repo and holds code only. `SURFACESCANNER_DATA` lives outside the repo and
   holds every engagement's scopes, outputs, reports, logs and signals. The repo
   never carries client data or secrets, and nothing client-specific is ever
   committed or pushed. No client-identifying value is hardcoded in code, in a
   template or in UI markup. It is always read from engagement data at runtime.
   A real finding, count, host or name never lands in a spec, a doc or a comment
   either. State the general principle, never the engagement that taught it.

4. **No database, no orchestrator.** State is files on disk. Each runner is a
   standalone process that does one cycle and writes a file. The scanning flow
   imports no AI stack and no datastore.

5. **One uniform module contract.** Every layer module exposes
   `async def run(scope, config, db=None)` and returns `{"findings": [...]}`. A
   module that lacks a key or a tool skips itself and contributes nothing. It
   never fails the layer it belongs to.

6. **Signals are sanitised.** No page bytes and no confidential payloads reach a
   signal file. Anything whose severity cannot be mapped floors to SEV5, so a
   finding never inflates its own severity.

7. **The operator owns triage and control.** The console is read-only over
   signals and never computes findings itself. Triage state (confirmed, false
   positive, notes) changes only on an explicit operator action, never as a side
   effect of a scan. Control actions shell out only through the guarded path.

8. **Tests are the gate and the regression net.** No change ships with a red or
   unrun test. A shipped layer keeps a test that proves its contract still holds,
   so a later change cannot break it unnoticed. A check that was not run stays
   visible rather than being claimed as passed.

9. **Deliverables are deterministic.** Reports are built without AI and send no
   traffic to the client.

10. **Language and text.** Code and identifiers are in English. Repo prose stays
    plain and human, with no em dashes and no semicolons.

11. **Shipped contracts are stable.** A layer talks to the rest of the engine
    only through its `run(scope, config, db)` contract and its signal schema. A
    change to a shipped layer stays backward compatible. A new need is met by
    adding to the signal, never by breaking what another layer already reads. A
    breaking change requires a spec update and a version bump. Touch only what
    the task requires and never refactor working code as a side effect.
