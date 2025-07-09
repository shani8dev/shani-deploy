#!/usr/bin/env bash
#
# startup-check: detect fallback boot and prompt for rollback on Shani OS
# Invoked at user startup to ensure correct slot rollback if needed.

set -Eeuo pipefail
IFS=$'\n\t'

# Configuration
readonly CURRENT_SLOT_FILE="/data/current-slot"
readonly BOOT_FAILURE_FILE="/data/boot_failure"
readonly LOG_TAG="startup-check"

# Logging
log() {
  echo "[$(date '+%F %T')] $*"
  logger -t "$LOG_TAG" "$*"
}
err() {
  log "ERROR: $*"
  exit 1
}
trap 'log "Exiting."' EXIT

# Detect terminal
find_terminal() {
  [[ -n "${TERMINAL_EMULATOR:-}" && -x "$(command -v "$TERMINAL_EMULATOR")" ]] && echo "$TERMINAL_EMULATOR" && return
  [[ -n "${COLORTERM:-}" && -x "$(command -v "$COLORTERM")" ]] && echo "$COLORTERM" && return

  local terms=(
    kgx gnome-terminal tilix xfce4-terminal konsole lxterminal mate-terminal
    deepin-terminal alacritty kitty wezterm foot terminator guake tilda
    hyper xterm urxvt st screen tmux
  )
  for term in "${terms[@]}"; do
    if command -v "$term" &>/dev/null; then
      echo "$term"
      return
    fi
  done
  err "No supported terminal found. Install one of: ${terms[*]}"
}
TERMINAL=$(find_terminal)
log "Using terminal: $TERMINAL"

# Terminal command builder
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
    screen|tmux|guake|tilda)
      echo "bash -lc \"$cmd\"" ;;
    *) err "Unhandled terminal: $emu" ;;
  esac
}

# Determine current and booted slot
CURRENT_SLOT=$(<"$CURRENT_SLOT_FILE" 2>/dev/null || echo "blue")
BOOTED_SLOT=$(grep -o 'subvol=[^, ]*' /proc/cmdline | cut -d= -f2 | sed 's/^@//')
[[ -z "$BOOTED_SLOT" ]] && BOOTED_SLOT="$CURRENT_SLOT"

# Skip if slots match
if [[ "$BOOTED_SLOT" == "$CURRENT_SLOT" ]]; then
  log "Booted slot matches current slot ('$CURRENT_SLOT'). No action needed."
  exit 0
fi

# Check if rollback is needed
if [[ -f "$BOOT_FAILURE_FILE" ]]; then
  FAILED_SLOT=$(<"$BOOT_FAILURE_FILE")
  if [[ "$FAILED_SLOT" != "$BOOTED_SLOT" ]]; then
    log "Failure was recorded for '$FAILED_SLOT', but system booted into '$BOOTED_SLOT'. No rollback needed."
    exit 0
  fi

  log "System booted fallback slot '$BOOTED_SLOT' (expected: '$CURRENT_SLOT'). Prompting rollback."

  # GUI prompt
  if command -v yad &>/dev/null; then
    yad --question --title="Rollback Prompt" \
        --text="System booted from fallback slot ($BOOTED_SLOT) instead of expected ($CURRENT_SLOT).\n\nRollback now?" \
        --ok-label="Rollback" --cancel-label="Cancel"
    RET=$?
  elif command -v zenity &>/dev/null; then
    zenity --question --title="Rollback Prompt" \
           --text="System booted from fallback slot ($BOOTED_SLOT) instead of expected ($CURRENT_SLOT).\n\nRollback now?"
    RET=$?
  else
    err "YAD or Zenity required for rollback prompt."
  fi

  # Execute rollback
  if [[ "$RET" -eq 0 ]]; then
    log "User confirmed rollback."
    CMD="pkexec /usr/local/bin/shani-deploy --rollback"
    TERMINAL_CMD=$(build_cmd "$TERMINAL" "$CMD")
    log "Launching rollback: $TERMINAL_CMD"
    bash -c "$TERMINAL_CMD" || err "Failed to launch rollback in terminal."
  else
    log "User cancelled rollback."
  fi
fi

exit 0

