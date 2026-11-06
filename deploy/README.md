# Deploy, always-on watchers

Two ways to keep the lookalike engine running on its own. Run both for full
coverage. One sweeps on a cadence, the other reacts in real time.

| Unit | Kind | Catches |
|---|---|---|
| `lookalike-watch@<scope>.timer` | cadence, every 6h | registration, DNS and MX changes, the full re-score and the Excel pool |
| `certstream-watch@<scope>.service` | always on | a brand new lookalike the moment its TLS certificate is issued |
| `dmarc-watch@<scope>.timer` | cadence, weekly | email-auth posture regressions: DMARC/SPF/DKIM/MX weakening or a DMARC policy downgrade (regression-only) |

The instance name after the `@` is the scope file stem. A scope at
`$SURFACESCANNER_DATA/scopes/acme.yaml` is driven by `...@acme`.

## Before you enable anything

1. Set your paths. The units read `/opt/surfacescanner/.env` and run from
   `/opt/surfacescanner`. Edit both unit files if your install lives elsewhere.
   The `.env` must set `SURFACESCANNER_ROOT`, `SURFACESCANNER_DATA` and
   `SURFACESCANNER_TMP`.
2. Put the engagement scope under the data root, not in the repo, for example
   `$SURFACESCANNER_DATA/scopes/acme.yaml`.

## Cadence watcher

```bash
mkdir -p ~/.config/systemd/user
cp deploy/lookalike-watch@.service deploy/lookalike-watch@.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lookalike-watch@acme.timer

# watch it
systemctl --user list-timers 'lookalike-watch@*'
journalctl --user -u lookalike-watch@acme.service -f
```

Change the cadence in the `.timer` with `OnUnitActiveSec` (`1d` daily, `1w`
weekly).

## Real-time watcher

```bash
cp deploy/certstream-watch@.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now certstream-watch@acme
journalctl --user -u certstream-watch@acme -f
```

If it will not stay up, the websocket client extra is probably missing. Install
it, then `systemctl --user restart certstream-watch@acme`.

## Keep it running after logout

User services stop when you log out unless lingering is on.

```bash
loginctl enable-linger "$USER"
```

## A note on egress

These units send active traffic to suspect third-party hosts from wherever they
run. For continuous use that should be the disposable egress host, not an
analyst workstation, so the contact is attributable to the engagement and never
ties a suspect domain back to you. Run the units there, or point the install's
network egress at it.
