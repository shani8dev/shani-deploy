#!/usr/bin/env bash
#
# shani-update: per-user update checker for Shani OS
# Invoked by systemd --user via timer or manually.

IFS=$'\n\t'

# Configuration
declare -r DEFER_DELAY=300
declare -r UPDATE_CHANNEL="stable"
declare -r BASE_URL="https://sourceforge.net/projects/shanios/files"
declare -r LOCAL_VERSION_FILE="/etc/shani-version"
declare -r LOCAL_PROFILE_FILE="/etc/shani-profile"
declare -r LOG_TAG="shani-update"

# Logging functions
log() {
  local msg="$*"
  echo "[$(date '+%F %T')] $msg"
  logger -t "$LOG_TAG" "$msg"
}
err() {
  log "ERROR: $*"
  exit 1
}
trap 'log "Exiting."' EXIT

# Detect terminal emulator
find_terminal() {
  # Prioritize environment variables
  for var in TERMINAL_EMULATOR COLORTERM; do
    local emu=${!var-}
    if [[ -n "$emu" ]] && command -v "$emu" &>/dev/null; then
      echo "$emu"; return
    fi
  done

  # Fallback list
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

  err "No supported terminal found. Install one of: ${terms[*]}"
}
TERMINAL=$(find_terminal)
log "Using terminal: $TERMINAL"

# Helper: build a terminal invocation string
build_cmd() {
  local emu="$1"; shift
  local cmd="$*"
  case "$emu" in
    kgx|gnome-terminal|tilix|xfce4-terminal|lxterminal|mate-terminal|deepin-terminal)
      echo "$emu -- bash -ic '$cmd'" ;;
    konsole)
      echo "$emu --hold -e bash -ic '$cmd'" ;;
    alacritty|kitty|wezterm|foot|xterm|urxvt|st)
      echo "$emu -e bash -ic '$cmd'" ;;
    terminator)
      echo "$emu -x bash -ic '$cmd'" ;;
    guake|tilda)
      echo "bash -ic '$cmd'" ;;
    hyper)
      echo "$emu --command bash -ic '$cmd'" ;;
    screen|tmux)
      echo "bash -ic '$cmd'" ;;
    *) err "Unhandled terminal: $emu" ;;
  esac
}

# Read local version/profile
defaults() {
  local file=$1 default=$2
  [[ -r "$file" ]] && read -r val < "$file" || val="$default"
  echo "$val"
}
LOCAL_VERSION=$(defaults "$LOCAL_VERSION_FILE" 0)
LOCAL_PROFILE=$(defaults "$LOCAL_PROFILE_FILE" default)

# Sanitize
LOCAL_VERSION=${LOCAL_VERSION//[^0-9]/}
LOCAL_PROFILE=${LOCAL_PROFILE//[^A-Za-z]/}

# Fetch remote info
CHANNEL_URL="$BASE_URL/$LOCAL_PROFILE/$UPDATE_CHANNEL.txt"
REMOTE_IMAGE=$(curl -fSLs --retry 3 --retry-delay 5 --max-time 30 "$CHANNEL_URL") || err "Failed fetching info from $CHANNEL_URL"

# Expect format: shanios-<version>-<profile>.zst
if [[ ! $REMOTE_IMAGE =~ ^shanios-([0-9]+)-([A-Za-z]+)\.zst$ ]]; then
  err "Bad remote info format: $REMOTE_IMAGE"
fi
REMOTE_VERSION="${BASH_REMATCH[1]}"
REMOTE_PROFILE="${BASH_REMATCH[2]}"

# Exit if already up-to-date
if [[ "$LOCAL_VERSION" -eq "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
  log "Up-to-date (v$LOCAL_VERSION-$LOCAL_PROFILE)."
  exit 0
fi

# Prompt user for action
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
    notify-send "Shani OS: v$LOCAL_VERSION → v$REMOTE_VERSION" || true
    return 1
  fi
}

if decide_action; then
  log "Starting update to v$REMOTE_VERSION..."

  # Build update command with elevated privileges
  UPDATE_CMD=(
    systemd-inhibit --what=shutdown:sleep:idle:handle-lid-switch:handle-power-key:handle-suspend-key:handle-hibernate-key \
      --who='Shani OS Update' --why='Applying system update' \
      /usr/local/bin/shani-deploy || read -p 'Press Enter to continue…'
  )

  # Wrap with pkexec to preserve GUI context
  FULL_CMD="pkexec env DISPLAY=\"$DISPLAY\" XAUTHORITY=\"$XAUTHORITY\" bash -c '${UPDATE_CMD[*]}'"
  TERMINAL_CMD=$(build_cmd "$TERMINAL" "$FULL_CMD")

  eval "$TERMINAL_CMD" || err "Deployment failed."

  # Notify & optionally reboot
  if command -v yad &>/dev/null; then
    yad --title="Update Complete" --width=300 \
        --text="Update to v$REMOTE_VERSION complete." \
        --button="Restart Now":0 --button="Close":1
    CHOICE=$?
  else
    notify-send "Update v$REMOTE_VERSION complete." || true
    read -rp "Reboot now? [y/N]: " yn
    [[ $yn =~ ^[Yy] ]] && CHOICE=0 || CHOICE=1
  fi

  if [[ $CHOICE -eq 0 ]]; then
    log "Rebooting system..."
    pkexec shutdown -r now
  else
    log "Update applied; reboot postponed."
  fi
else
  log "Deferring update by $DEFER_DELAY seconds."
  systemd-run --user --unit="${LOG_TAG}-defer" --on-active="$DEFER_DELAY" "$0"
fi

exit 0

