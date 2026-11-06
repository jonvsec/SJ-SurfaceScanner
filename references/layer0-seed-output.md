# Layer 0 seed output contract

Layer 0's product is NOT only a readable dossier. It is the scope that every
later layer runs against. So layer 0 must also emit a structured, typed,
confidence-scored, state-tagged asset inventory. The dossier is the human view of
the same data. If a run produces only prose, it has not done the layer-0 job.

No em dashes, no en dashes, no semicolons.

## The asset record

Every asset layer 0 attributes is one record with these fields:

| Field | Meaning |
|---|---|
| `type` | one of `apex`, `domain`, `ip`, `netblock`, `asn`, `cloud_account`, `entra_tenant`, `code_org`, `mobile_app`, `technology` (a stack component, CMS, framework, CDN, analytics, payment or SaaS provider), `entity` (legal company), `person` |
| `value` | the scalar (the domain, the GUID, the registry code, the LEI, the name) |
| `canonical_id` | the id of the one entity or asset this belongs to after canonicalization (see below) |
| `scope` | `in-scope-confirmed` or `attribution-only` (the authorization interlock) |
| `state` | for brands and entities: `live`, `acquired`, `divested`, `winding-down`, `parked`, `defunct`, with an `as_of` date |
| `ownership_signal` | the concrete signal that ties it to the target (shared Entra tenant, registry code, reverse-WHOIS, cert SAN, GLEIF relationship). Required. |
| `confidence` | `verified`, `inferred`, or `lead`, as a field, not only prose |
| `source` | the retrievable locator and the catalog row it came from |
| `as_of` | date of retrieval |

Emit these as the signal records the engine already consumes, mapping
`confidence` and `ownership_signal` into the description and `scope`/`state` into
the entity tags. The point is machine-consumable scope, not a report a person has
to re-key.

## Pending structures, defined now and emitted empty (schema lock)

These four structures are part of the LOCKED contract even though the modules
that fill them are not built yet. They are emitted present-but-empty today, so
the sanctions screen, the subsidiary resolver and the investigative module land
next as field fillers, NOT as a breaking change to a contract already frozen.

- **`candidate_domains[]`** (filled by the subsidiary and brand name to domain
  resolver, verdict set by the S2 ownership gate). Each entry:
  `{domain, ownership_signal, signal_type, confidence, verdict}` where `verdict`
  is `pending | owned | lookalike | third_party`. A candidate is never
  auto-promoted: it stays `pending` until S2 or an operator sets the verdict.
- **`investigative[]`** (filled by the investigative modules, ICIJ first). Each
  entry: `{type, source, node_id, confidence}` where `type` is
  `litigation | regulatory | offshore | adverse_media`. Empty today.
- **`sanctions_screen`** (filled by the sanctions and PEP screen). One object:
  `{status, list, matched_entity, screened_at}` where `status` is
  `clear | hit | unscreened`. Today it is always `unscreened`, which is honest:
  a `clear` must come from a screen that actually ran, never from silence.
- **`ruled_out[]`** (the same-name gate output, already produced in spirit).
  Each entry: `{entity, reason}` naming a same-name or same-sector company that
  was excluded and why.

Until a module fills one, it is present and empty (`[]`, or `sanctions_screen`
with `status: unscreened`). An empty structure is a real state, not a missing
field: `unscreened` is NOT `clear`.

## The authorization interlock (hard)

- Every asset is tagged `in-scope-confirmed` or `attribution-only`.
- `in-scope-confirmed` means the contracted domain itself and anything the signed
  authorization names. Everything layer 0 discovers by spreading scope starts as
  `attribution-only`.
- Nothing moves from `attribution-only` to active testing without an operator
  promoting it against the signed authorization. Layer 0 never auto-promotes.
- This is what lets scope spread aggressively without ever auto-testing an asset
  the engagement is not authorized to touch. Spreading scope and enforcing the
  boundary are the same step.

## Asset state, because scope is time-dependent

M&A changes ownership, so scope is a point-in-time statement.

- A `divested` or `defunct` brand is OUT of scope even if it still resolves.
- An `acquired` brand is newly IN scope (as attribution until authorization names
  it).
- A `winding-down` asset may change state during the engagement, so carry the
  `as_of` date and the trigger (a sale, a wind-down notice).
- Record the state from a primary or dated source, not from stale press.

## Canonicalization (the inverse of the disambiguation gate)

The disambiguation gate stops same-name-different-company. Canonicalization does
the opposite: it merges the many strings that are ONE entity.

- "OÜ Example", "Example OÜ", "Example Group OÜ" may be one entity or three,
  resolve it by registry code, not by string. Assign one `canonical_id` and list
  the alias strings.
- Merge a person's name variants and transliterations to one `canonical_id`.
- Without this the asset graph fragments and later layers double-count.

## Coverage statement (a senior deliverable always has one)

End layer 0 with an explicit list of what was searched and came back EMPTY, so
the next analyst and the next run do not redo it. A negative is a result. Record
the source, the query, and the date of the empty check.

## Sanctions and embargo escalation (not just a finding)

A sanctions, OFAC, embargo, or clear PEP hit on the target entity or a principal
does not simply raise a finding and flow on. It can constrain the engagement
itself (who may be paid, what may be done). Layer 0 HALTS that thread and
escalates to the operator with the source and the matched identity, rather than
continuing to spread scope around a potentially sanctioned subject. The operator
decides whether and how the engagement proceeds.
