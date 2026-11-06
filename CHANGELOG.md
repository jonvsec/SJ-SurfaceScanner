# Changelog

All notable changes to this project are documented here.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning (MAJOR.MINOR.PATCH).

## [0.1.0] - 2026-10-25

First public cut. The lookalike and brand protection vertical is working end to
end. It finds the domains an attacker would register to impersonate a brand,
keeps only the ones that actually exist, scores each one from SEV1 to SEV5, and
writes a sanitised signal file ready for ingest. It runs fully local and uses no
AI.

### Added
- Lookalike pipeline, functional. dnstwist permutation generation, then
  `--registered --mxcheck`, then RDAP enrichment, then MX driven SEV1 to SEV5
  scoring.
- `tools/lookalike_watch.py`, the cadence runner. It runs one cycle against a
  scope and writes a sanitised JSONL signal file (metadata only, no page bytes,
  no confidential data) under the engagement's own data directory.
- `tools/lookalike_report.py`, the Excel deliverable. Two sheets. All Candidates
  holds the full permutation pool. Registered Lookalikes holds only the ones
  that resolve, with score and SEV.
- `tools/certstream_watch.py`, a real time Certificate Transparency watcher. It
  degrades gracefully if the websocket client is absent. Not yet exercised
  against a live stream.
- Code and data separation. `SURFACESCANNER_ROOT` holds code only. Engagement
  data (scopes, outputs, reports, logs, signals) lives outside the repo under
  `SURFACESCANNER_DATA/engagements/<client>/`.
- Full folder skeleton (layer0 to layer4) kept from the start, with each phase
  that is not promoted yet marked WIP.

### Fixed
- Dropped dnstwist failure sentinels such as `!ServFail` from DNS record lists.
  They no longer leak into signals as bogus IPs, falsely flag mail capability,
  or inflate severity.

[0.1.0]: https://github.com/jonvsec/EAS/releases/tag/v0.1.0
