# Architecture

This is the design overview of the Continuous External Attack Surface (EAS)
engine. It explains why the tool exists, the loop that keeps it running, and how
the pieces fit together. Read it alongside the `README.md` (what ships today)
and `deploy/README.md` (how the watchers are installed).

## Why this tool runs

The job is continuous external attack surface monitoring, per client, per
engagement. A company's external surface is not static. New lookalike and
phishing domains get registered, new subdomains appear, certificates are issued,
credentials leak into breach and infostealer corpora, and new CVEs become
known-exploited. A point-in-time pentest misses all of that the day after it
ends.

So the engine watches the surface over time. For each client it keeps rediscovering
what exists, scores every finding on a SEV1 to SEV5 scale, and raises the new
ones as alerts an operator can triage into a deliverable. Three constraints shape
every design decision:

1. **Stay off the client by default.** Every capability declares a gate
   (passive, semi, active). The network boundary enforces the scope mode, so a
   semi or active command can never fire inside a passive scope. Most phases are
   contactless.
2. **Keep code and client data strictly apart.** `SURFACESCANNER_ROOT` is this
   repo and holds code only. `SURFACESCANNER_DATA` lives outside the repo and
   holds every engagement's scopes, outputs, reports, logs and signals under
   `DATA/engagements/<client>/`. The repo never carries client data.
3. **No database, no orchestrator.** Each runner is a standalone process that
   does one cycle and writes a file. State is files on disk, not a service to
   operate.

## The loop

There is no in-process `while True` driving the engine. The loop is driven by
**systemd user units**, one set per client per phase, and the runners are
short-lived.

```
  systemd timer fires  (or a long-running feed is up)
        |
        v
  work service runs ONE watcher cycle
        |   (layer_watch.py / subdomain_watch.py / lookalike_watch.py)
        v
  the cycle discovers  ->  normalises to signals  ->  writes a JSONL signal file
        |                                                under DATA/engagements/<client>/
        v
  the operator console reads the signal files and reflects the latest state
```

One cycle, in detail:

1. A systemd unit starts. Scheduled autowatchers are timers (for example
   `lookalike-watch@<slug>.timer`, every 6 hours, and `subdomain-rescan@<slug>.timer`,
   weekly). Live feeds are long-running services (for example
   `certstream-watch@<slug>.service`, always on). The instance name after the
   `@` is the client slug.
2. The unit runs a watcher for that scope. The generic runner, `layer_watch.py`,
   takes a layer number, discovers every module promoted into that layer's
   package, and calls each module's `async def run(scope, config, db=None)`.
   Each module is bounded by a per-module wall-clock budget, so one that hangs on
   an external call is skipped and the layer goes on. A module that needs a key
   or a tool it cannot find skips itself and contributes nothing, so a
   half-configured layer runs clean and empty rather than failing.
3. The runner converts each finding into one sanitised signal: a stable dedup
   id, a title, a scrubbed description, a SEV1 to SEV5 severity, the source
   class, and a scalar-only entity list. No page bytes and no confidential
   payloads reach the signal file.
4. The runner writes the full current signal set for that layer to the client's
   own JSONL file every cycle, so the file is the latest state, not an
   append-only history. A sidecar `.seen.json` preserves each finding's
   first-seen timestamp across cycles, which is what lets the console tell a new
   finding from an existing one.
5. The console reads those files. It is read-only over signals. It renders the
   counts, the per-phase status, the severity breakdown, the relationship map,
   and the triage tables straight from the files on disk.

The cadence lives in the `.timer` units, not in code. Change
`OnUnitActiveSec` to retune a phase. Nothing polls in the application layer.

## The console (`tools/panel.py`)

The operator console is a stdlib HTTP server (`ThreadingHTTPServer`, HTML built
with f-strings, no web framework). It is the read-and-control surface over the
engine, and it is deliberately thin.

- **Read path.** It reads the signal files and the per-client sidecar state and
  renders the fleet overview and the per-client page. It never computes findings
  itself.
- **Control path.** The only state-changing actions shell out to
  `systemctl --user`: toggle an autowatcher on or off (`enable --now` /
  `disable --now` a timer or service), fire a one-shot run, run all phases once,
  or emergency-stop everything. A target guardrail gates anything that starts
  work, server-side, so the UI cannot bypass it. Stopping is always allowed.
- **Single source of truth.** The phase registry (`PHASES`), the real commands
  each module runs (`COMMANDS`), and the editable knobs (`KNOBS`) are all plain
  data in the console. The UI shows exactly what the engine runs because it reads
  the same constants the units run from. Knob edits are validated to a single
  safe token with no shell metacharacters, so a saved value can tune a flag but
  never add one or chain a command.
- **Triage state is the operator's.** Confirmed, false-positive and note state
  for findings lives in per-client sidecar JSON under
  `DATA/engagements/<client>/state/`. The console writes it only on an explicit
  operator action, never as a side effect of a scan.

Adding a new vertical later is one entry in `PHASES` plus its systemd unit. No
other console code changes.

## The layers

The phase registry mirrors the layer packages, so the console shows the whole
engine, one card per layer, with not-yet-promoted phases reading as what is
coming.

| Layer | Name | What it answers | Promoted so far |
|---|---|---|---|
| 0 | Corporate Intelligence | Who the target is, legally, and the Entra tenant that anchors the rest | corporate intelligence run |
| 1 | OSINT | What public sources and people leak | lookalike and brand protection, live certificate feed |
| 2 | Subdomain and Network Infrastructure | What infrastructure exists | passive and active subdomain enumeration, weekly re-scan |
| 2.5 | Surface Recon | What the discovered surface exposes | surface recon run (email and DNS security, favicon correlation) |
| 3 | Digital Footprint and Breach | Who works there and what has leaked | footprint and breach run, credential leak watcher |
| 4 | Kill Chain and Sector Intelligence | What it all means | EPSS and CISA KEV scoring |

Each module exposes the same `run(scope, config, db)` contract and returns
`{"findings": [...]}`. That uniform shape is what lets `layer_watch.py` drive any
layer without knowing what its modules do, and what lets the console treat every
phase the same way.

## Signal format

One signal is the normalised unit every layer produces and the console consumes.

```json
{
  "dedup_id":     "sha1 of source_class|value, stable across cycles",
  "title":        "short human title",
  "description":  "scrubbed, truncated, no payloads",
  "severity":     "SEV1..SEV5",
  "source":       "Continuous EAS / <layer name>",
  "source_class": "the finding type",
  "entities":     [{"type": "domain|ip|email|cve|asset", "value": "..."}],
  "first_seen":   "carried across cycles from the .seen.json sidecar",
  "last_seen":    "this cycle"
}
```

Severity floors to SEV5 (informational) for anything it cannot map, so a
miscategorised finding never inflates its own severity.

## Deliverables

`tools/surface_report.py` builds the monitoring report (Word and PDF) and the
single-finding early alert from a client's current signals. Deterministic, no AI.
The console triggers it and the reports land in the engagement's own reports
folder. This path is read-only over signals and starts no scan, so it sends no
traffic to the client.
