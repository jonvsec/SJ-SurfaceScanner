# Technical plan: Spec NNN

Read the constitution and the spec before writing this. No code here, only the
design. State which RF each part covers.

## Module structure
<Which files and packages. Which layer. The run(scope, config, db) entry points
and what each returns. (RF-...)>

## Data model
<Signal shape, any sidecar state, the JSONL file written. No page bytes, no
payloads. (RF-...)>

## Algorithm
<The core logic step by step, where it is non-obvious. (RF-...)>

## Technical decisions
<Each decision with the alternative that was rejected and why. For example:
stdlib over a framework, inject the clock for testability, skip on missing key
rather than fail.>

## Scope and gate enforcement
<How this respects the declared gate. What the network boundary allows in this
mode.>

## Test strategy
<What is unit tested, what uses tmp paths, what is a smoke test. One or more
tests per RF.>
