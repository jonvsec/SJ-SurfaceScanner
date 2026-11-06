# Dev requests: upstream technique adoption

A batch of techniques lifted from the upstream OSINT skill family, written up as
implementation requests for the SurfaceScanner engine. Each item names the layer
it belongs in, what to build, the exact data or formula, the gate it runs under
(passive, semi, active), and the acceptance criteria. Nothing here changes
`panel.py` behaviour beyond what each item states, and the console stays
read-only over signals.

No em dashes, no en dashes, no semicolons.

Delivery order: Tier 1 first (it upgrades the continuous engine the operator
already relies on), then Tier 2 (new footprint discovery), then Tier 3 (identity
and email depth).

A note on how these fit the existing model. Today a finding is one signal with a
`dedup_id = sha1(source_class|value)`, a `first_seen` carried in the
`.seen.json` sidecar, a `last_seen` set this cycle, and a SEV1 to SEV5 label.
Several Tier 1 items build directly on top of that, they do not replace it.

---

# Tier 1. Continuous engine, dedup, scoring

## T1.1 Finding lifecycle state machine

**Layer:** all. Lives in the signal writer (`layer_watch.py`) and the triage
sidecar under `DATA/engagements/<client>/state/`.

**Problem it solves.** Right now a finding is new or not-new by first-seen date.
There is no lifecycle, so a resolved finding that reappears, or one the operator
has accepted the risk on, has no distinct state. This is the rigorous version of
the "same domain reappears, update it, do not go blind" rule.

**Build.**

- Add a stable fingerprint distinct from the value-only `dedup_id`:
  `fingerprint = sha1(f"{source_class}\x1f{dedup_id}\x1f{normalized_title}")[:16]`.
  `normalized_title` is the title lowercased, digit runs collapsed to `#`, and
  whitespace collapsed, so "8 lookalike domains active" and "11 lookalike domains
  active" are one identity, not two.
- Carry a lifecycle record per fingerprint in the triage sidecar:
  `{state, first_seen, last_seen, age_cycles, updated_by, updated_at}`.
- States: `open -> triaged -> {risk_accepted | resolved | false_positive}`, and
  `resolved -> open` (reopen) when the fingerprint reappears.
- Reconciliation each cycle:
  - new fingerprint -> `open`, `age_cycles = 1`.
  - reappears while `open` or `triaged` -> `age_cycles += 1`.
  - reappears while `resolved` -> reopen to `open`, stamp `updated_by = auto`.
  - absent this cycle AND state is `open` or `triaged` AND last_seen is an
    earlier cycle -> auto-resolve, `updated_by = auto`.
  - `risk_accepted` and `false_positive` are never touched by reconciliation.
- Suppression rule for all downstream views and scoring: suppress ONLY
  `false_positive` and `resolved`. `risk_accepted` stays visible and still counts
  in the aggregate risk score and any attack-path logic. This is deliberate.
- SLA days per severity for an ageing view: SEV1 7, SEV2 14, SEV3 30, SEV4 90,
  SEV5 none. Derive `overdue | due_soon (within 3 days) | on_track | none`.

**Gate:** none, this is bookkeeping over signals already produced.

**Acceptance.**

- A finding that disappears for one cycle then returns keeps ONE fingerprint and
  shows `reopened`, not a second row.
- Marking a finding `risk_accepted` keeps it in the risk score. Marking it
  `false_positive` removes it from the score and the triage table.
- Digit-only title changes (the lookalike count going 8 to 11) do not create a
  new fingerprint. A new confirmed domain (new `dedup_id`) does.

## T1.2 Diff engine with per-type tracked attributes

**Layer:** engine-wide. New module `tools/diff.py`, consumes two signal
snapshots for a layer (or the whole client) and emits a diff.

**Build.**

- New and removed assets are a set-diff on the signal `dedup_id`.
- "Changed" is computed only over a declared attribute list per entity or signal
  type, never a blind whole-record compare:
  - `webapp`: status, title, server, tech, waf, cdn, jarm, favicon_hash,
    content_hash, redirect_off_scope.
  - `certificate`: not_after, issuer, self_signed.
  - `port` / `service`: ip, port, transport, product.
  - `bucket`: provider, listable, public.
  - `credential`: email, breach.
  - `domain` / `subdomain` / `ip` / `email` / `person` / `asn` / `netblock` /
    `typosquat_domain`: existence only, no attribute diff.
- An IP re-point surfaces as a paired removed plus new (the value is in the key),
  never a confusing "changed" row.
- Output sections, severity-desc within each, cap 50 per section with a
  "and N more" line: NEW findings, RESOLVED, NEW assets, REMOVED, CHANGED (old
  value to new value per attribute).

**Gate:** none.

**Acceptance.**

- Re-running a cycle with no surface change produces an empty diff.
- A certificate renewal shows one CHANGED row on `not_after`, not a remove plus
  add.
- A host moving IP shows one REMOVED and one NEW, cleanly paired.

## T1.3 Hot-type alert rule

**Layer:** alerting (feeds T1.4). Reads the diff from T1.2.

**Build.**

- A diff entry is alert-worthy when EITHER a new finding is at or above the
  configured threshold (default SEV3), OR a new asset belongs to the hot set
  `{credential, typosquat_domain, bucket, repo}`, in which case it alerts
  regardless of severity.
- `typosquat_domain` is the active brand-impersonation class this engine already
  raises, so a newly confirmed active lookalike always alerts even if its own SEV
  is low. This is the "never let me go blind on a new impersonation" rule.

**Gate:** none.

**Acceptance.**

- A new confirmed active lookalike domain fires an alert even at SEV4.
- A new SEV5 webapp title change does not fire.

## T1.4 Durable alert outbox

**Layer:** new subsystem `tools/alert_outbox.py` plus a worker unit. Does NOT
live in `panel.py`.

**Build.**

- "Queued is not delivered." Every alert is enqueued to a durable store
  (`DATA/engagements/<client>/state/outbox.jsonl`). Enqueue success is not
  delivery success.
- Dedup key: `f"{kind}:" + sha1(url + json.dumps(payload, sort_keys=True))[:16]`,
  suppressed only against still-pending entries.
- Backoff on delivery failure: `delay = min(60 * 2**attempts, 21600)` seconds, so
  120, 240, 480, 960, 1920, 3840, 7680, then dead-letter after 8 attempts.
- Worker runs on a short timer (for example every 30 seconds), retries pending,
  purges delivered older than 14 days. Expose `retry(id)` and
  `retry_all_failed()`.
- Webhook payload is Slack-compatible: a `text` field plus a structured envelope
  (which scans were compared, new findings total and hot count, new hot assets).

**Gate:** none (outbound to the operator's own webhook, not the client).

**Acceptance.**

- Killing the webhook receiver and restarting it later still delivers the queued
  alerts, in order, without duplicates.
- An alert that fails 8 times lands in dead-letter and is visible for manual
  retry.

## T1.5 Aggregate engagement risk score and dollar-loss (FAIR)

**Layer:** 4 (Kill Chain and Sector Intelligence). Per-finding SEV1 to SEV5
stays exactly as is. This ADDS one engagement-level score.

**Build the score.**

- `risk = round(likelihood * impact * 100, 1)`, grade bands: <=20 A, <=40 B,
  <=60 C, <=80 D, >80 F.
- Independent-evidence combiner used throughout:
  `combine(weights) = 1 - prod(1 - w_i)`, clamp to [0,1], empty -> 0.
- Exposure E over all non-suppressed findings: severity weights SEV1 1.0,
  SEV2 0.4, SEV3 0.1, SEV4 0.02, SEV5 0.0. `S = sum(weights)`,
  `E = min(1 - exp(-S / 25), 1 - 1e-15)`. Proven-critical floor: if an owned
  (owner_confidence >= 70), confirmed SEV1 finding exists, `E = max(E, 0.5)`.
- Threat T, combine of: CISA KEV present 0.90, `min(1, epss_max) * 0.7`, held
  leaked creds 0.80, ransomware or chatter hit at HIGH or CRITICAL 0.85, any
  attack-path chain at or above 85 present a flat 0.60 (binary, not stacked).
- `likelihood = combine([E, T])`.
- Impact I, ownership-gated, max not average:
  `I = max(asset_weight * owner_confidence / 100)` over assets. asset_weight:
  credential or secret 1.0, exposed admin panel or auth bypass category 0.9,
  payment hostname token {pay, payment, billing, checkout, wallet} 0.9, internal
  token {jenkins, gitlab, grafana, kibana, vault, jira, confluence, vpn,
  internal, staging, admin, sso, idp, okta, keycloak, adfs} 0.85, api endpoint
  with auth not required 0.7, webapp or subdomain or ip or domain or service 0.4,
  typosquat 0.1, else 0.1. Tokens match whole hostname segments, so `payroll`
  does not match `pay`.

**Build the dollar model.**

- Cost bands USD per record: `{low: 150, expected: 165, high: 200}` (IBM and
  Ponemon ~165).
- Records come only from leaked-credential findings, keys `employees` plus
  `users`. Cross-source dedup is `records = max(by_source.values())`, MAX across
  sources, never summed, so two breach feeds reporting the same corp do not
  double-count.
- `low/expected/high = records * band`,
  `annualized = expected * (breach_likelihood / 100)` where breach_likelihood is
  the threat factor T scaled to 0 to 100, NOT the composite risk.
- Zero records yields zero dollars, never a fabricated figure.

**Gate:** none, pure computation over existing signals.

**Acceptance.**

- An engagement with one confirmed owned SEV1 scores no lower than if E alone
  were small (the 0.5 floor holds).
- Two breach feeds each reporting 1000 records for the same client yield 1000
  records, not 2000.
- The board one-pager shows a grade A to F, the dollar band, and a tri-state
  headline (dollar band, or "N confirmed-critical exposures" when records are 0
  but criticals exist, or "No quantified record exposure").

## T1.6 Ownership-gated "no finding at all"

**Layer:** 1 (lookalike and brand protection) and 2.5 (surface recon, buckets).
A module-contract rule.

**Build.**

- A candidate becomes a finding (or even an informational signal) ONLY when
  ownership or activity is proven. Unproven, it stays an asset in the layer-0
  seed inventory and produces no signal. This is the same rule already applied to
  lookalike domains (a pooled, unregistered or dormant domain is not a finding
  and not informational), generalised to buckets and any attributed asset.
- For a bucket, ownership is proven by one of: name contains a trusted target
  token, the name was observed in a CNAME chain or certificate SAN or Wayback
  URL, or a listed object key names the target. Only then: listable -> SEV1
  confirmed, public-read non-listable -> SEV3, exists-denied (403 or 400) ->
  SEV5 info.
- Exception: a dangling-CNAME takeover is a finding regardless of ownership gate,
  because the live CNAME is itself the ownership proof. SEV2, confirmed.

**Gate:** passive for discovery, the bucket existence probe is semi (one GET per
candidate, no object body fetched).

**Acceptance.**

- A public bucket with no tie to the target produces zero signals, it is only an
  attribution-only asset in the layer-0 inventory.
- The documented 171-item false-positive flood does not recur.
- A live subdomain CNAME pointing at an unclaimed bucket still raises the
  takeover finding.

## T1.7 CTI and ransomware-leak chatter monitoring

**Layer:** 1 (OSINT) as a new long-running watcher, or 4 if you prefer sector
intel. Passive.

**Build.**

- Poll free sources on their own cadence: ransomwatch
  `raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json` (300s),
  ransomware.live `https://api.ransomware.live/v2/recentvictims` (300s), Reddit
  per-sub RSS `https://www.reddit.com/r/<sub>/.rss` (600s), Hacker News Algolia
  `https://hn.algolia.com/api/v1/search` (600s). GitHub gist search and Telegram
  `https://t.me/s/<channel>` are optional and keyed.
- Persist every leak-site row to a durable corpus (natural-key dedup) regardless
  of the watchlist, so a later watchlist entry can search history.
- Watchlist match modes: literal substring, glob (fnmatch), regex, with a bad
  regex falling back to literal. Match on client domain, brand, keyword, or
  email.
- Severity by source kind: leak site with a domain match plus a named ransomware
  group -> CRITICAL, else HIGH. Forum with an initial-access-broker phrase plus a
  domain plus a price -> HIGH. Promotion into a signal is always TENTATIVE
  confidence and an INFO_DISCLOSURE class until an operator confirms.
- Retroactive rescan: when a new watchlist entry is added, scan the stored corpus
  and insert matches PRE-MARKED as already alerted, so you get the history
  without an alert storm on day one.
- Hard rule: an ambient hit (the brand word appearing with no client-specific
  context) is blocked from promotion.

**Gate:** passive (all public third-party feeds, nothing to the client).

**Acceptance.**

- Adding a client to the watchlist surfaces prior leak-site mentions as history,
  with no alert fired for the backfill.
- A ransomware leak-site post naming the client domain fires a CRITICAL alert
  through the T1.4 outbox.

---

# Tier 2. New footprint discovery

## T2.1 GetFederationInformation SOAP sibling discovery

**Layer:** 0 (Corporate Intelligence, the Entra tenant anchor).

**Build.**

- Unauthenticated POST to
  `https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc` with header
  `SOAPAction: "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`
  and a body carrying `<autodiscover:Domain>{domain}</autodiscover:Domain>`.
- Parse every `<Domain>` value from the response (namespace-agnostic). These are
  all the domains federated into the same M365 tenant, so sibling brands and
  subsidiaries with no DNS trail back to the seed.
- Emit each sibling as an `attribution-only` layer-0 asset, never auto-promoted
  to active testing, tied to the tenant GUID the layer already resolves.

**Gate:** passive (one unauthenticated call to Microsoft infra, nothing to the
client).

**Acceptance.** For a known multi-brand M365 tenant, the sibling list includes
brands that DNS and certificate-transparency enumeration do not reveal, each
tagged attribution-only with the shared tenant GUID as the ownership signal.

## T2.2 Dark-netblock recovery via org-first RIR

**Layer:** 0 discovery, feeds Layer 2 scope.

**Build.**

- ARIN: `https://whois.arin.net/rest/orgs;name={Name}*` (Accept JSON) for org
  handles, then `/rest/org/{HANDLE}/nets` for ranges (convert start and end to
  CIDR) and `/rest/org/{HANDLE}/asns`.
- RIPE: `https://rest.db.ripe.net/search.json?query-string={name}&type-filter=organisation&flags=no-referenced`
  for the ORG handle, then an inverse-org search
  `?query-string={ORG-HANDLE}&inverse-attribute=org&type-filter=inetnum&type-filter=inet6num&type-filter=aut-num`.
- Precision gate: exact normalised-slug match against the known identity aliases
  from layer 0, not a substring match, or you will graft a namesake.
- Hyperscaler-scope guard: if the registrant is AWS, GCP, Azure, Cloudflare,
  Akamai or Fastly, materialise ONLY the single block the seed IP sits in and tag
  it `shared_hosting_cdn`, never `seed_owned`. Owned ranges (brand-substring
  registrant) materialise most-specific prefixes up to about 200.

**Gate:** passive (RIR queries only).

**Acceptance.** For an org that holds its own ASN, the recovered netblocks
include ranges with zero DNS pointing at them, and a client hosted behind
Cloudflare does not pull Cloudflare's shared range in as owned.

## T2.3 Corporate family tree, keyless

**Layer:** 0.

**Build.**

- GLEIF: resolve name to LEI
  `https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]={name}&page[size]=1`
  (Accept `application/vnd.api+json`), then direct children
  `/api/v1/lei-records/{LEI}/direct-children?page[size]=100`.
- SEC EDGAR full-text
  `https://efts.sec.gov/LATEST/search-index?q=%22{name}%22&forms=10-K` with a
  descriptive User-Agent, then the filing's Exhibit 21 for the true subsidiary
  roster (US filers only).
- Wikidata SPARQL `https://query.wikidata.org/sparql`, properties P856 official
  website, P355 subsidiary, P749 parent, P1830 owner of.
- Combine signals with the T1.5 combiner `1 - prod(1 - w_i)`. Recursion rule:
  downward only, recurse on exact LEI, never re-resolve a child by name (that is
  how namesakes get grafted).

**Gate:** passive.

**Acceptance.** For a known corporate group the tree matches the filed parent and
child set, and feeding a common-word brand does not pull in an unrelated
same-name company.

## T2.4 Offline AWS account-ID decode

**Layer:** shared utility, used wherever an AWS key surfaces (Layer 2.5 and
Layer 3). A pure function, no network.

**Build.**

- From an `AKIA`/`ASIA`/`AROA`/`AIDA` key: uppercase, take the first 20 chars,
  validate the 4-char prefix plus `[A-Z2-7]{16}`, base32-decode the 16-char body
  to 10 bytes, `z = int.from_bytes(decoded[:6], "big")`,
  `account = (z & 0x7FFFFFFFFF80) >> 7`, zero-pad to 12. Reject if > 999999999999.
- Screen against the 14 AWS documentation example accounts and never report them:
  123456789012, 111122223333, 222233334444, 333344445555, 444455556666,
  555566667777, 666677778888, 777788889999, 888899990000, 999900001111,
  012345678901, 000000000000, 123412341234, 101010101010.
- Prefix meaning: AKIA IAM user key, ASIA STS temp, AROA role, AIDA user.
- Ownership and severity: key on an in-scope host -> owned, SEV3, FIRM. Key on a
  third-party host -> referenced, SEV5, FIRM. Severity ceiling SEV3 unless a live
  read-only validation confirms it (and validation is a separate, gated step the
  operator authorises, never automatic).

**Gate:** none for the decode (offline). Any live validation is active and
operator-gated.

**Acceptance.** AWS's published example access-key id decodes to its
documentation example account id. A key whose decode lands on a documentation
example account produces no finding.

## T2.5 Dependency-confusion two-part confirmation

**Layer:** 2.5 (surface recon) when a manifest or JS bundle is in hand.

**Build.**

- Mine manifests: `package.json` (all dep blocks), `package-lock.json`, `.npmrc`
  (`{scope}:registry=` or bare `registry=` is a private-registry signal),
  `requirements.txt` and `pyproject.toml` (with their index-url and source
  directives), and any `.js`/`.mjs`/`.cjs`/`.map` body for scoped `@scope/name`.
- Internal signal: strong when an npm scope is bound to a private registry or a
  PyPI private index is configured, medium when a name matches an org-namespace
  token (at least 4 chars, not a generic word like corp or solutions). The
  namespace token comes from the registrable brand label, never the leftmost DNS
  label.
- Two-part confirmation contract: raise a finding only when there is an internal
  signal AND the public registry returns 404 (`registry.npmjs.org` or
  `pypi.org`). Fail closed on 200, 403, 5xx or timeout.
- npm scope-claimability nuance: for `@scope/pkg`, check
  `https://www.npmjs.com/org/{scope}` and `https://www.npmjs.com/~{scope}`,
  registerable only if BOTH 404. Do not use the search API, it returns total 0
  for privately owned empty scopes and lies.
- Severity: strong -> SEV2 FIRM, medium -> SEV3 TENTATIVE, never confirmed from
  OSINT alone.

**Gate:** semi (reads public registries, nothing to the client).

**Acceptance.** A private `@acme/` scope whose org and user pages both 404 raises
a SEV2 dependency-confusion finding. The same scope with either page present
raises nothing.

---

# Tier 3. Identity and email depth

## T3.1 Email spoofability verdict

**Layer:** 2.5 (email and DNS security already runs here). This adds a single
verdict on top of the record dump. Passive DNS only.

**Build.**

- Resolve the verdict in priority order, short-circuiting:
  1. more than one DMARC record at `_dmarc.{domain}` (the whole set is ignored
     per RFC 7489) -> SPOOFABLE, SEV2.
  2. SPF terminal qualifier `+all` or a bare `all` -> SPOOFABLE, SEV2 (wins over
     any DMARC branch).
  3. no DMARC -> SEV2.
  4. DMARC `p=none` or `p=` missing or malformed -> SEV2.
  5. `p=quarantine` -> SEV3.
  6. `p=reject` but `pct<100` -> SEV3.
  7. `p=reject pct=100` but the effective subdomain policy is not
     quarantine or reject -> SEV3 (subdomain vector).
  8. else fully enforced -> not spoofable, SEV5 info.
- Effective subdomain policy: explicit `sp=` if present, else inherit the apex
  `p=`. An explicit `sp=none` under `p=reject` is the real gap (case 7). Severity
  ceiling is SEV2, never SEV1.
- SPF lookup budget (RFC 7208): count 1 each for `include`, `a`, `mx`, `ptr`,
  `exists`, `redirect`, free for `ip4`, `ip6`, `all`. Exceeding 10 lookups or 2
  void lookups is a PermError that fails open (receivers treat it as no SPF) ->
  raise it.
- SPF-include takeover: a dead `include:` target that NXDOMAINs may be
  re-registerable and inherit SPF-pass authority. NXDOMAIN is a lead only (verify
  availability via RDAP), a NOERROR with no TXT is void not dead, a timeout or
  SERVFAIL is transient and never flagged. Base SEV3, escalate only once
  registration availability is confirmed.

**Gate:** passive.

**Acceptance.** A domain with `p=none` returns SPOOFABLE SEV2. A domain with
`p=reject pct=100 sp=none` returns SEV3 with the subdomain-vector reason. A
transient DNS failure on an include never produces a takeover finding.

## T3.2 Identity oracles and posture tells

**Layer:** 0 (Entra tenant) for the posture tells, 2.5 for the enumeration
oracle. Caps and gating are mandatory.

**Build the passive posture tells (Layer 0, passive).**

- Azure Seamless SSO: GET
  `https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed`,
  a 401 with `WWW-Authenticate: Negotiate` means the `AZUREADSSOACC$` account
  exists. Record as an informational posture signal.
- Microsoft Defender for Identity: DNS-resolve
  `{tenant-prefix}sensorapi.atp.azure.com` (prefix from the `.onmicrosoft.com`
  name), resolves means MDI is deployed. This is a defensive tell, record it as
  good-news context for the client, not a finding.
- Device-code posture: GET
  `https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration`,
  a non-null `device_authorization_endpoint` is the prerequisite for device-code
  phishing. SEV3 at most, informational.

**Build the enumeration oracle (Layer 2.5, semi, hard-capped).**

- Microsoft: POST `https://login.microsoftonline.com/common/GetCredentialType`
  with `{"Username": "<email>", "isOtherIdpSupported": true}`. Read
  `IfExistsResult`: 0 exists in tenant, 6 exists in a different federated tenant
  (a cross-tenant signal worth recording), 5 throttled (back off). No password is
  ever sent.
- Okta: POST `https://{org}.okta.com/api/v1/authn` with
  `{"username": "<email>", "password": "<placeholder>"}`, the placeholder is
  required by the request shape and is never a real password. `errorCode`
  `E0000004` indicates a known account.
- Hard caps, non-negotiable: at most 20 candidates per tenant, interest-ranked
  before truncating (admin, security, ops local-parts first). Every oracle
  evidence record carries `credential_submitted: false` as the audit boundary.
  Only enumerate tenants that layer 0 already resolved.

**Gate:** posture tells passive, the enumeration oracle is semi and must be
blocked inside a passive scope by the network boundary, same as any semi command.

**Acceptance.** In a passive scope the oracle never fires and only the passive
posture tells run. In a semi scope the oracle respects the 20-candidate cap and
every record shows `credential_submitted: false`.

---

# Summary table

| Item | Layer | Gate | Core artifact |
|---|---|---|---|
| T1.1 lifecycle | all | none | fingerprint + state machine |
| T1.2 diff | engine | none | per-type attribute diff |
| T1.3 hot-type alert | alerting | none | hot-set `{credential, typosquat_domain, bucket, repo}` |
| T1.4 outbox | new subsystem | none | durable queue + backoff |
| T1.5 FAIR score | 4 | none | A-F grade + dollar band |
| T1.6 ownership gate | 1, 2.5 | passive/semi | no finding unless owned |
| T1.7 CTI chatter | 1 or 4 | passive | ransomware leak + forum poller |
| T2.1 federation SOAP | 0 | passive | sibling domains, no DNS trail |
| T2.2 dark netblock | 0 to 2 | passive | org-first RIR ranges |
| T2.3 family tree | 0 | passive | GLEIF/EDGAR/Wikidata graph |
| T2.4 AWS acct decode | 2.5, 3 | none | offline 12-digit account id |
| T2.5 dependency confusion | 2.5 | semi | internal signal + public 404 |
| T3.1 email spoofability | 2.5 | passive | one HIGH/MED/INFO verdict |
| T3.2 identity oracle | 0, 2.5 | passive/semi | posture tells + capped enum |
