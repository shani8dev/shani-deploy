#!/usr/bin/env bash
#
# startup-check: detect fallback boot and prompt for rollback on Shani OS

set -Eeuo pipefail
IFS=$'\n\t'

readonly CURRENT_SLOT_FILE="/data/current-slot"
readonly BOOT_FAILURE_FILE="/data/boot_failure"
readonly LOG_TAG="startup-check"

log() {
  echo "[$(date '+%F %T')] $*"
  logger -t "$LOG_TAG" "$*"
}

err() {
  log "ERROR: $*"
  exit 1
}

trap 'log "Exiting."' EXIT

find_terminal() {
  local terms=(
    kgx gnome-terminal tilix xfce4-terminal konsole lxterminal mate-terminal
    deepin-terminal alacritty kitty wezterm foot terminator
    hyper xterm urxvt st
  )
  for term in "${terms[@]}"; do
    command -v "$term" &>/dev/null && echo "$term" && return
  done
  err "No supported terminal found."
}

TERMINAL=$(find_terminal)
log "Using terminal: $TERMINAL"

build_cmd() {
  local emu="$1"; shift
  local cmd="$*"

  case "$emu" in
    kgx|gnome-terminal|tilix|xfce4-terminal|lxterminal|mate-terminal|deepin-terminal)
      echo "$emu -- bash -lc \"$cmd\"" ;;
    konsole)
      echo "$emu --hold -e bash -lc \"$cmd\"" ;;
    alacritty|kitty|wezterm|foot|xterm|urxvt|st)
      echo "$emu -e bash -lc \"$cmd\"" ;;
    terminator)
      echo "$emu -x bash -lc \"$cmd\"" ;;
    hyper)
      echo "$emu --command bash -lc \"$cmd\"" ;;
    *)
      err "Unhandled terminal: $emu" ;;
  esac
}

CURRENT_SLOT=$(<"$CURRENT_SLOT_FILE" 2>/dev/null || echo "blue")
BOOTED_SLOT=$(grep -o 'subvol=[^, ]*' /proc/cmdline | cut -d= -f2 | sed 's/^@//')
[ -z "$BOOTED_SLOT" ] && BOOTED_SLOT="$CURRENT_SLOT"

if [[ "$BOOTED_SLOT" == "$CURRENT_SLOT" ]]; then
  log "Booted slot matches current slot ($CURRENT_SLOT)."
  exit 0
fi

[ ! -f "$BOOT_FAILURE_FILE" ] && exit 0

FAILED_SLOT=$(<"$BOOT_FAILURE_FILE")

# 🔑 Correct rollback condition
if [[ "$FAILED_SLOT" != "$CURRENT_SLOT" ]]; then
  log "Recorded failure '$FAILED_SLOT' does not match expected '$CURRENT_SLOT'."
  exit 0
fi

log "Fallback detected. Booted='$BOOTED_SLOT', failed='$FAILED_SLOT'."

if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  if command -v yad &>/dev/null; then
    yad --question \
      --title="Rollback Prompt" \
      --text="System failed to boot from slot '$FAILED_SLOT'.\n\nRollback now?" \
      --ok-label="Rollback" --cancel-label="Cancel"
    RET=$?
  elif command -v zenity &>/dev/null; then
    zenity --question \
      --title="Rollback Prompt" \
      --text="System failed to boot from slot '$FAILED_SLOT'.\n\nRollback now?"
    RET=$?
  else
    err "YAD or Zenity required for rollback prompt."
  fi

  if [[ "$RET" -eq 0 ]]; then
    log "User confirmed rollback."
    CMD="pkexec /usr/local/bin/shani-deploy --rollback"
    TERMINAL_CMD=$(build_cmd "$TERMINAL" "$CMD")
    bash -c "$TERMINAL_CMD" || err "Failed to launch rollback."
  else
    log "User cancelled rollback."
  fi
fi

exit 0
