#!/usr/bin/env bash
# shani-update: per-user update checker for Shani OS via systemd --user
set -Eeuo pipefail
IFS=$'\n\t'

# Constants
readonly DEFER_DELAY=300
readonly UPDATE_CHANNEL="stable"
readonly BASE_URL="https://sourceforge.net/projects/shanios/files"
readonly LOCAL_VERSION_FILE="/etc/shani-version"
readonly LOCAL_PROFILE_FILE="/etc/shani-profile"
readonly LOG_TAG="shani-update"
readonly LOG_FILE="${XDG_CACHE_HOME:-$HOME/.cache}/shani-update.log"

# Logging
log() {
  local msg="$*"
  echo "[$(date '+%F %T')] $msg" | tee -a "$LOG_FILE"
  logger -t "$LOG_TAG" "$msg"
}
err() {
  log "ERROR: $*"
  exit 1
}
trap 'log "Exiting."' EXIT

# Terminal detection
find_terminal() {
  for var in TERMINAL_EMULATOR COLORTERM; do
    local emu="${!var:-}"
    if [[ -n "$emu" && -x "$(command -v "$emu" 2>/dev/null)" ]]; then
      echo "$emu"; return
    fi
  done
  local terms=(
    kgx gnome-terminal tilix xfce4-terminal konsole lxterminal mate-terminal
    deepin-terminal alacritty kitty wezterm foot terminator guake tilda
    hyper xterm urxvt st screen tmux
  )
  for term in "${terms[@]}"; do
    if command -v "$term" &>/dev/null; then
      echo "$term"; return
    fi
  done
  err "No terminal found. Please install one of: ${terms[*]}"
}
TERMINAL=$(find_terminal)
log "Using terminal: $TERMINAL"

# Read version/profile
read_file_or_default() {
  local file="$1" default="$2"
  [[ -r "$file" ]] && head -n1 "$file" || echo "$default"
}
LOCAL_VERSION="$(read_file_or_default "$LOCAL_VERSION_FILE" "0" | tr -cd '0-9')"
LOCAL_PROFILE="$(read_file_or_default "$LOCAL_PROFILE_FILE" "default" | tr -cd 'A-Za-z')"

# Remote fetch
CHANNEL_URL="$BASE_URL/$LOCAL_PROFILE/$UPDATE_CHANNEL.txt"
REMOTE_IMAGE="$(curl -fsSL --retry 3 --retry-delay 5 --max-time 30 "$CHANNEL_URL")" || err "Failed to fetch info from $CHANNEL_URL"

if [[ "$REMOTE_IMAGE" =~ ^shanios-([0-9]+)-([A-Za-z]+)\.zst$ ]]; then
  REMOTE_VERSION="${BASH_REMATCH[1]}"
  REMOTE_PROFILE="${BASH_REMATCH[2]}"
else
  err "Bad remote format: $REMOTE_IMAGE"
fi

# Check if update is needed
if [[ "$LOCAL_VERSION" -eq "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
  log "Already up-to-date (v$LOCAL_VERSION-$LOCAL_PROFILE)"
  exit 0
fi

# GUI prompt
decide_action() {
  if command -v yad &>/dev/null; then
    yad --title="Shani OS Update" --width=400 --center \
        --text="New update available!\nCurrent: v$LOCAL_VERSION-$LOCAL_PROFILE\nRemote: v$REMOTE_VERSION-$REMOTE_PROFILE\nChoose:" \
        --button="Update Now":0 --button="Remind Me Later":1 \
        --timeout=60 --timeout-label="Remind Me Later"
    return $?
  elif command -v zenity &>/dev/null; then
    zenity --question --title="Shani OS Update" \
           --text="Current: v$LOCAL_VERSION-$LOCAL_PROFILE\nRemote: v$REMOTE_VERSION-$REMOTE_PROFILE" \
           --ok-label="Update Now" --cancel-label="Remind Me Later"
    return $?
  else
    notify-send "Shani OS Update" "v$LOCAL_VERSION → v$REMOTE_VERSION available"
    return 1
  fi
}

# Terminal launcher
build_cmd() {
  local emu="$1"; shift
  local cmd="$*"
  case "$emu" in
    kgx|gnome-terminal|tilix|xfce4-terminal|lxterminal|mate-terminal|deepin-terminal)
      echo "$emu -- bash -ic \"$cmd\"" ;;
    konsole)
      echo "$emu --hold -e bash -ic \"$cmd\"" ;;
    alacritty|kitty|wezterm|foot|xterm|urxvt|st)
      echo "$emu -e bash -ic \"$cmd\"" ;;
    terminator)
      echo "$emu -x bash -ic \"$cmd\"" ;;
    guake|tilda|screen|tmux)
      echo "bash -ic \"$cmd\"" ;;
    hyper)
      echo "$emu --command bash -ic \"$cmd\"" ;;
    *) err "Unhandled terminal: $emu" ;;
  esac
}

# GUI accepted
if decide_action; then
  log "Starting update to v$REMOTE_VERSION..."

  # Preserve GUI env
  DISPLAY_ENV="${DISPLAY:-:0}"
  XAUTH_ENV="${XAUTHORITY:-$HOME/.Xauthority}"

  UPDATE_CMD='/usr/local/bin/shani-deploy || read -p "Press Enter to continue…"'
  FULL_CMD="systemd-inhibit --what=shutdown:sleep:idle:handle-* --who='Shani OS Update' --why='System update in progress' bash -c '$UPDATE_CMD'"

  # Run with pkexec in terminal
  PKEXEC_CMD="pkexec env DISPLAY=\"$DISPLAY_ENV\" XAUTHORITY=\"$XAUTH_ENV\" bash -c \"$FULL_CMD\""
  TERMINAL_CMD="$(build_cmd "$TERMINAL" "$PKEXEC_CMD")"

  log "Launching terminal command: $TERMINAL_CMD"
  bash -c "$TERMINAL_CMD" || err "Update failed."

  # Prompt reboot
  if command -v yad &>/dev/null; then
    yad --title="Update Complete" --width=300 \
        --text="Update to v$REMOTE_VERSION complete." \
        --button="Restart Now":0 --button="Close":1
    CHOICE=$?
  else
    notify-send "Update v$REMOTE_VERSION complete."
    read -rp "Reboot now? [y/N]: " yn
    [[ "$yn" =~ ^[Yy]$ ]] && CHOICE=0 || CHOICE=1
  fi

  if [[ "$CHOICE" -eq 0 ]]; then
    log "Rebooting system..."
    pkexec shutdown -r now
  else
    log "User postponed reboot."
  fi
else
  log "User deferred update. Rescheduling in $DEFER_DELAY seconds..."
  systemd-run --user --unit="${LOG_TAG}-defer" --on-active="${DEFER_DELAY}s" "$0"
fi

exit 0

