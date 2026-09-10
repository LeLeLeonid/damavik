#!/bin/sh
# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
#
# Install Damavik on a Linux host: brain + sensor units, config, state dirs.
#
# Deliberately plain POSIX sh with no package manager, no curl | sh, and no
# binary download. Everything it installs comes from this checkout, so you can
# read every byte before running it. Requires root for the systemd units; run
# with DRY_RUN=1 to see the commands without executing them.

set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"
SHARE_DIR="${SHARE_DIR:-/usr/share/damavik}"
CONFIG_DIR="${CONFIG_DIR:-/etc/damavik}"
STATE_DIR="${STATE_DIR:-/var/lib/damavik}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
DRY_RUN="${DRY_RUN:-0}"
ENABLE="${ENABLE:-1}"

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

log() { printf '%s\n' "damavik: $*"; }
run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '  (dry run) %s\n' "$*"
    else
        "$@"
    fi
}

need_root() {
    if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" != "1" ]; then
        log "this script needs root (systemd units live in $UNIT_DIR)."
        log "Re-run with sudo, or set DRY_RUN=1 to preview."
        exit 1
    fi
}

log "repository: $REPO_ROOT"
need_root

# --- python -----------------------------------------------------------------
log "checking the Python runtime"
if ! command -v python3 >/dev/null 2>&1; then
    log "python3 not found. Damavik needs Python 3.11 or newer."
    exit 1
fi
PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
log "python $PY_VERSION"
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    log "Python 3.11+ is required (found $PY_VERSION)."
    exit 1
fi

# --- prove it works before installing anything ------------------------------
log "running the self-test (offline, no root)"
if [ "$DRY_RUN" != "1" ]; then
    ( cd "$REPO_ROOT/brain" && python3 -m damavik.cli selftest ) || {
        log "self-test failed; aborting install."
        exit 1
    }
fi

# --- files ------------------------------------------------------------------
log "installing the brain to $SHARE_DIR"
run mkdir -p "$SHARE_DIR"
run cp -R "$REPO_ROOT/brain/damavik" "$SHARE_DIR/damavik"
run cp -R "$REPO_ROOT/rules" "$SHARE_DIR/rules"

log "installing the damavik launcher to $BIN_DIR"
run mkdir -p "$BIN_DIR"
if [ "$DRY_RUN" != "1" ]; then
    cat >"$BIN_DIR/damavik" <<LAUNCHER
#!/bin/sh
# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
exec python3 "$SHARE_DIR/damavik/cli.py" "\$@"
LAUNCHER
    chmod 0755 "$BIN_DIR/damavik"
fi

# --- config -----------------------------------------------------------------
run mkdir -p "$CONFIG_DIR"
if [ "$DRY_RUN" = "1" ] || [ ! -f "$CONFIG_DIR/damavik.yaml" ]; then
    log "installing the example config to $CONFIG_DIR/damavik.yaml"
    run cp "$REPO_ROOT/config/damavik.example.yaml" "$CONFIG_DIR/damavik.yaml"
else
    log "keeping the existing $CONFIG_DIR/damavik.yaml (not overwritten)"
fi

# --- state ------------------------------------------------------------------
log "creating the state directory $STATE_DIR"
run mkdir -p "$STATE_DIR"
if [ "$DRY_RUN" != "1" ]; then
    # The state directory holds command lines and hostnames: same care as a
    # shell history file.
    chmod 0750 "$STATE_DIR"
fi

# --- units ------------------------------------------------------------------
for unit in damavik-brain.service damavik-sensor.service; do
    log "installing $UNIT_DIR/$unit"
    run cp "$REPO_ROOT/packaging/systemd/$unit" "$UNIT_DIR/$unit"
done

if [ "$DRY_RUN" != "1" ]; then
    run systemctl daemon-reload
    if [ "$ENABLE" = "1" ]; then
        log "enabling and starting the services"
        run systemctl enable --now damavik-brain.service
        run systemctl enable --now damavik-sensor.service
    else
        log "ENABLE=0: units installed but not started."
        log "  systemctl enable --now damavik-brain damavik-sensor"
    fi
fi

log "done."
log "next:"
log "  damavik status                 # what it sees"
log "  damavik alerts -v              # ranked alerts with reasons"
log "  damavik serve                  # dashboard on 127.0.0.1"
log "  journalctl -u damavik-brain -f"
