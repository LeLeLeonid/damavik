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
# Non-root installs are supported for prefixes (`PREFIX=~/.local`) and for tests
# that install into a throwaway tree; the systemd units still need root to be
# loaded.  Without this, the only way to exercise the installer was as root on a
# real machine, which is exactly how the broken launcher below went unnoticed.
ALLOW_NONROOT="${ALLOW_NONROOT:-0}"

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
    [ "$DRY_RUN" = "1" ] && return 0
    [ "$ALLOW_NONROOT" = "1" ] && return 0
    if [ "$(id -u)" -ne 0 ]; then
        log "this script needs root (systemd units live in $UNIT_DIR)."
        log "Re-run with sudo, set DRY_RUN=1 to preview, or set"
        log "ALLOW_NONROOT=1 to install into a prefix you own."
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
# The demo capture ships too: `damavik demo` and `damavik selftest` are how an
# operator proves the install works, and they must work from anywhere.
run mkdir -p "$SHARE_DIR/tests/fixtures"
run cp "$REPO_ROOT/tests/fixtures/attack-chain.jsonl" "$SHARE_DIR/tests/fixtures/"

log "installing the damavik launcher to $BIN_DIR"
run mkdir -p "$BIN_DIR"
if [ "$DRY_RUN" != "1" ]; then
    # `python3 share/damavik/cli.py` fails: cli.py uses relative imports, so it
    # is only importable as part of the package.  Run it as a module with the
    # share directory on the path instead - the same shape the docs use
    # (`cd brain && python3 -m damavik.cli ...`).
    cat >"$BIN_DIR/damavik" <<LAUNCHER
#!/bin/sh
# SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
# SPDX-License-Identifier: GPL-3.0-only
PYTHONPATH="$SHARE_DIR\${PYTHONPATH:+:\$PYTHONPATH}" exec python3 -m damavik.cli "\$@"
LAUNCHER
    chmod 0755 "$BIN_DIR/damavik"
fi

# --- verify what was just installed -----------------------------------------
# The gate that would have caught the broken launcher: run the *installed*
# command, not the checkout.  It must score the demo capture with no root, no
# network and no help from the current directory.
if [ "$DRY_RUN" != "1" ]; then
    log "verifying the installed command"
    if ! "$BIN_DIR/damavik" --offline selftest >/dev/null 2>&1; then
        log "the installed command failed its self-test:"
        "$BIN_DIR/damavik" --offline selftest || true
        log "installation is incomplete; nothing was enabled."
        exit 1
    fi
    log "  $BIN_DIR/damavik selftest: OK"
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
run mkdir -p "$UNIT_DIR"
for unit in damavik-sensor.service damavik-dashboard.service; do
    log "installing $UNIT_DIR/$unit"
    run cp "$REPO_ROOT/packaging/systemd/$unit" "$UNIT_DIR/$unit"
done

if [ "$DRY_RUN" != "1" ]; then
    # Driving systemd needs a running bus.  The binary can exist without one
    # (containers, WSL, chroots, the test rig this script is verified in), and
    # `/run/systemd/system` is not a reliable proxy either, so ask systemd
    # itself and degrade gracefully: the units are installed either way.
    if ! systemctl daemon-reload 2>/dev/null; then
        log "systemd is not usable here: units are installed but not loaded."
        log "  start the monitor by hand: damavik sensor | damavik run"
        log "  and the dashboard with:   damavik serve"
    elif [ "$ENABLE" = "1" ]; then
        log "enabling and starting the services"
        run systemctl enable --now damavik-sensor.service
        run systemctl enable --now damavik-dashboard.service
    else
        log "ENABLE=0: units installed but not started."
        log "  systemctl enable --now damavik-sensor damavik-dashboard"
    fi
fi

log "done."
log "next:"
log "  damavik status                 # what it sees"
log "  damavik alerts -v              # ranked alerts with reasons"
log "  damavik serve                  # dashboard on 127.0.0.1"
log "  journalctl -u damavik-sensor -f"
