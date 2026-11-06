# layer0

WIP. This phase lives in the full engine and is promoted here one phase at a time.
The folder structure is kept so the architecture is visible from the start.

## Modules

- `estate_expander.py` — ownership-pivot estate expansion. Mines analytics and
  ad-tech IDs (GA4 `G-`, Universal Analytics `UA-`, GTM `GTM-`, AdSense
  `ca-pub-`) and favicon MurmurHash3 from each in-scope seed, then reverse-looks
  them up to discover sibling root domains run by the same operator. This is a
  DISCOVERY expander and belongs in layer 0, not in layer2_5 surface recon: it
  turns one seed into more owned roots that later layers then work on. The
  layer2_5 `favicon_correlation` module only correlates hosts (and emits IPs)
  late in the pipeline, so it does not grow the root estate. Reverse backends
  are optional and key-gated (`PUBLICWWW_API_KEY`, `SHODAN_API_KEY`), with a
  keyless best-effort path and a fully passive fall-through that still reports
  every ID and hash as a pivot primitive. Discovered roots are emitted as
  `estate_root` findings tagged `attribution-only` with the shared ID or hash as
  the ownership signal, and are never fetched or auto-promoted to active testing.
