#!/usr/bin/env bash
# Install the autowatcher units as systemd user units for a local or analyst
# box, generated from this checkout.
#
# The templates in this folder (lookalike-watch@.service and friends) target a
# production install at /opt/surfacescanner. On a dev or analyst machine the
# code lives somewhere else and there is often no virtualenv, so this script
# writes units that point at wherever this repository actually sits, the Python
# it finds, and the data root, then reloads systemd.
#
#   bash deploy/install-user-units.sh
#   systemctl --user start subdomain-passive@<client>.service
#
# The instance name is the scope file stem under $DATA/scopes, so a scope at
# $DATA/scopes/acme.yaml is driven by ...@acme.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
else
  PYTHON="$(command -v python3)"
fi
DATA="${SURFACESCANNER_DATA:-$HOME/surfacescanner-data}"
UNIT_DIR="$HOME/.config/systemd/user"
mkdir -p "$UNIT_DIR"

echo "[i] root   $ROOT"
echo "[i] python $PYTHON"
echo "[i] data   $DATA"
echo "[i] units  $UNIT_DIR"

# Shared head. EnvironmentFile is optional (the leading dash), so a missing
# .env does not fail the unit. It carries API keys only, the paths are baked in.
common_service() {   # $1 description
  cat <<UNIT
[Unit]
Description=$1
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$ROOT
EnvironmentFile=-$ROOT/.env
Environment=SURFACESCANNER_ROOT=$ROOT
Environment=SURFACESCANNER_DATA=$DATA
UNIT
}

# lookalike sweep, single shot on a timer
{ common_service "Lookalike watcher for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/lookalike_watch.py --scope $DATA/scopes/%i.yaml --once
Nice=10
TimeoutStartSec=3600
UNIT
} > "$UNIT_DIR/lookalike-watch@.service"

cat > "$UNIT_DIR/lookalike-watch@.timer" <<UNIT
[Unit]
Description=Run the lookalike sweep for %i on a cadence
[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true
Unit=lookalike-watch@%i.service
[Install]
WantedBy=timers.target
UNIT

# dmarc / email-auth posture watcher, single shot on a timer (sibling of
# lookalike-watch, regression-only). Posture changes slowly, so weekly.
{ common_service "Email-auth posture watcher for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/dmarc_watch.py --scope $DATA/scopes/%i.yaml --once
Nice=10
TimeoutStartSec=1800
UNIT
} > "$UNIT_DIR/dmarc-watch@.service"

cat > "$UNIT_DIR/dmarc-watch@.timer" <<UNIT
[Unit]
Description=Run the email-auth posture watcher for %i on a cadence
[Timer]
OnBootSec=10min
OnUnitActiveSec=1w
Persistent=true
Unit=dmarc-watch@%i.service
[Install]
WantedBy=timers.target
UNIT

# lookalike live feed, long running service
{ common_service "Lookalike live certificate feed for %i"
  cat <<UNIT
Type=simple
ExecStart=$PYTHON $ROOT/tools/certstream_watch.py --scope $DATA/scopes/%i.yaml
Restart=on-failure
RestartSec=10
[Install]
WantedBy=default.target
UNIT
} > "$UNIT_DIR/certstream-watch@.service"

# subdomain passive, single shot on a timer
{ common_service "Passive subdomain enumeration for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/subdomain_watch.py --scope $DATA/scopes/%i.yaml --mode passive --once
Nice=10
TimeoutStartSec=1800
UNIT
} > "$UNIT_DIR/subdomain-passive@.service"

cat > "$UNIT_DIR/subdomain-passive@.timer" <<UNIT
[Unit]
Description=Run passive subdomain enumeration for %i on a cadence
[Timer]
OnBootSec=5min
OnUnitActiveSec=12h
Persistent=true
Unit=subdomain-passive@%i.service
[Install]
WantedBy=timers.target
UNIT

# subdomain active, single shot on a timer, longer budget
{ common_service "Active subdomain enumeration for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/subdomain_watch.py --scope $DATA/scopes/%i.yaml --mode active --once
Nice=15
TimeoutStartSec=14400
UNIT
} > "$UNIT_DIR/subdomain-active@.service"

cat > "$UNIT_DIR/subdomain-active@.timer" <<UNIT
[Unit]
Description=Run active subdomain enumeration for %i on a cadence
[Timer]
OnBootSec=10min
OnUnitActiveSec=168h
Persistent=true
Unit=subdomain-active@%i.service
[Install]
WantedBy=timers.target
UNIT

# Generic per-layer watchers, single shot. Each runs one SurfaceScanner layer
# through tools/layer_watch.py and emits that layer's EAS signals. Adding a
# module to a layer is dropping its file into the layer package, no new unit.
#   corp-intel       layer 0   Corporate Intelligence   passive
#   surface-recon    layer 2.5 Surface Recon            active
#   footprint-breach layer 3   Digital Footprint/Breach passive
#   killchain-intel  layer 4   Kill Chain/Sector Intel  passive
{ common_service "Corporate Intelligence (layer 0) for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/layer_watch.py --scope $DATA/scopes/%i.yaml --layer 0 --mode passive --once
Nice=10
TimeoutStartSec=3600
UNIT
} > "$UNIT_DIR/corp-intel@.service"

{ common_service "Surface Recon (layer 2.5) for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/layer_watch.py --scope $DATA/scopes/%i.yaml --layer 2.5 --mode active --once
Nice=15
TimeoutStartSec=7200
UNIT
} > "$UNIT_DIR/surface-recon@.service"

{ common_service "Digital Footprint and Breach (layer 3) for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/layer_watch.py --scope $DATA/scopes/%i.yaml --layer 3 --mode passive --once
Nice=10
TimeoutStartSec=3600
UNIT
} > "$UNIT_DIR/footprint-breach@.service"

{ common_service "Kill Chain and Sector Intelligence (layer 4) for %i"
  cat <<UNIT
Type=oneshot
ExecStart=$PYTHON $ROOT/tools/layer_watch.py --scope $DATA/scopes/%i.yaml --layer 4 --mode passive --once
Nice=10
TimeoutStartSec=3600
UNIT
} > "$UNIT_DIR/killchain-intel@.service"

systemctl --user daemon-reload
echo "[i] installed and reloaded. Units are ready for the panel to drive."
