# Spec NNN: <slice name>

## Context and goal
<What problem this slice solves and why it is worth doing. One paragraph. Only
the what and the why. No stack, no file names, no algorithms. Those go in the
plan.>

## Users and actors
<Who or what uses this. For most layers this is the operator and the systemd
watcher.>

## Gate
<passive, semi or active. State it explicitly. See constitution principle 2.>

## User stories
- H1: As a <role> I want <action> so that <benefit>.

## Functional requirements (acceptance criteria in EARS)
- RF-1: WHEN <trigger>, THE SYSTEM shall <response> (expected result).
- RF-2: IF <unwanted condition>, THEN THE SYSTEM shall <response>.
- RF-3: WHILE <state>, THE SYSTEM shall <response>.
- RF-4: THE SYSTEM shall <permanent behaviour>.

Rules: one requirement is one sentence. Every requirement must be verifiable. No
unmeasurable adjectives. If you need an "and" to join two behaviours, that is two
requirements.

## Non-functional requirements
<Only the ones that apply: scope-mode safety, no payloads in signals, runtime
budget, platforms.>

## Edge cases
<Empty input, duplicates, missing key or tool, corrupt data file, rate limits,
timeouts.>

## Out of scope
<What this slice explicitly does not do. This is what stops the slice from
growing on its own.>

## Completion criteria
<For example: every RF covered by at least one test, the suite green, and a
manual demo of the main flow against an example scope.>

## Open questions
- [NEEDS CLARIFICATION: <question>]
