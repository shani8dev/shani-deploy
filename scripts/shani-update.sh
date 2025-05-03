#!/usr/bin/env bash
#
# shani-update: per-user update checker for Shani OS
# Invoked by systemd --user via timer or manually.

IFS=$'\n\t'

# Configuration
DEFER_DELAY=300
UPDATE_CHANNEL="stable"
BASE_URL="https://sourceforge.net/projects/shanios/files"
LOCAL_VERSION_FILE="/etc/shani-version"
LOCAL_PROFILE_FILE="/etc/shani-profile"
LOG_TAG="shani-update"

# Logging functions
log(){
  echo "[$(date '+%F %T')] $*"
  logger -t "$LOG_TAG" "$*"
}
err(){ log "ERROR: $*"; exit 1; }
trap 'log "Exiting."' EXIT

# Detect terminal emulator
define find_terminal() {
  [[ -n "${TERMINAL_EMULATOR-}" ]] && command -v "$TERMINAL_EMULATOR" &>/dev/null && { echo "$TERMINAL_EMULATOR"; return; }
  [[ -n "${COLORTERM-}" ]]      && command -v "$COLORTERM"      &>/dev/null && { echo "$COLORTERM";      return; }

  local terms=(
    kgx gnome-terminal tilix xfce4-terminal konsole lxterminal mate-terminal
    deepin-terminal alacritty kitty wezterm foot terminator guake tilda
    hyper xterm urxvt st screen tmux
  )
  for term in "${terms[@]}"; do
    command -v "$term" &>/dev/null && { echo "$term"; return; }
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
      echo "$emu -- bash -c '${cmd}'";;
    konsole)
      echo "konsole --hold -e bash -c '${cmd}'";;
    alacritty|kitty|wezterm|foot|xterm|urxvt|st)
      echo "$emu -e bash -c '${cmd}'";;
    terminator)
      echo "terminator -x bash -c '${cmd}'";;
    guake|tilda)
      echo "bash -c '${cmd}'";;
    hyper)
      echo "hyper --command bash -c '${cmd}'";;
    screen|tmux)
      echo "bash -c '${cmd}'";;
    *) err "Unhandled terminal: $emu";;
  esac
}

# Read local version/profile
LOCAL_VERSION=$(<"$LOCAL_VERSION_FILE" 2>/dev/null || echo 0)
LOCAL_PROFILE=$(<"$LOCAL_PROFILE_FILE" 2>/dev/null || echo default)
# sanitize
LOCAL_VERSION=${LOCAL_VERSION//[^0-9]/}
LOCAL_PROFILE=${LOCAL_PROFILE//[^A-Za-z]/}

# Fetch remote info
CHANNEL_URL="$BASE_URL/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
REMOTE_IMAGE=$(curl -fSLs --retry 3 --retry-delay 5 --max-time 30 "$CHANNEL_URL") 
if [[ $? -ne 0 ]]; then
  err "Failed fetching info from $CHANNEL_URL"
fi

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

# Prompt user
prompt_choice() {
  if command -v yad &>/dev/null; then
    yad --title="Shani OS Update" --width=400 --center \
        --text="New update available!\nCurrent: v$LOCAL_VERSION-$LOCAL_PROFILE\nRemote: v$REMOTE_VERSION-$REMOTE_PROFILE\nChoose:" \
        --button="Update Now":0 --button="Remind Me Later":1 \
        --timeout=60 --timeout-label="Remind Me Later"
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

action() { prompt_choice; echo $?; }
ACTION=$(action)

case $ACTION in
  0)
    log "Starting update to v$REMOTE_VERSION..."
    # build the update command with elevated privileges
    UPDATE_CMD="systemd-inhibit --what=shutdown:sleep:idle:handle-lid-switch:handle-power-key:handle-suspend-key:handle-hibernate-key \
      --who='Shani OS Update' --why='Applying system update' \
      /usr/local/bin/shani-deploy || read -p 'Press Enter to continue…'"

    # wrap with pkexec to preserve GUI context
    FULL_CMD="pkexec env DISPLAY=\"$DISPLAY\" XAUTHORITY=\"$XAUTHORITY\" bash -c '$UPDATE_CMD'"
    TERMINAL_CMD=$(build_cmd "$TERMINAL" "$FULL_CMD")

    eval "$TERMINAL_CMD" || err "Deployment failed."

    # Notify/reboot prompt
    if command -v yad &>/dev/null; then
      yad --title="Update Complete" --width=300 \
          --text="Update to v$REMOTE_VERSION complete." \
          --button="Restart Now":0 --button="Close":1
      CHOICE=$?
    else
      notify-send "Update v$REMOTE_VERSION complete." || true
      read -p "Reboot now? [y/N]: " yn; [[ $yn =~ ^[Yy] ]] && CHOICE=0 || CHOICE=1
    fi

    if [[ $CHOICE -eq 0 ]]; then
      log "Rebooting system..."
      pkexec shutdown -r now
    else
      log "Update applied; reboot postponed."
    fi
    ;;

  *)
    log "Deferring update by $DEFER_DELAY seconds."
    systemd-run --user --unit="${LOG_TAG}-defer" --on-active="$DEFER_DELAY" "$0"
    ;;

esac

exit 0

